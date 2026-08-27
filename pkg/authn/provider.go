package authn

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/authn/kubernetes"

	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
)

// defaultKeychainRefreshInterval is how often the cached keychain is rebuilt in
// the background when no explicit interval is configured.
const defaultKeychainRefreshInterval = 5 * time.Minute

// keychainBuildTimeout bounds a single background keychain build so a stalled
// rebuild can never wedge the refresher.
const keychainBuildTimeout = 30 * time.Second

// KeyChainProvider is used to provide k8s keychains, which can be used
// to authenticate certain requests like fetching resources from an OCI
// registry.
//
// The keychain is built once at startup and refreshed periodically in the
// background, so serving it to a request performs no I/O.
type KeyChainProvider struct {
	namespace        string
	imagePullSecrets []string
	refreshInterval  time.Duration

	// build constructs a keychain and reports whether the configured in-cluster
	// authenticators were built successfully. It is a field so tests can inject
	// a stub without a live cluster; production uses buildKeychain.
	build func(ctx context.Context) (authn.Keychain, bool)

	mu     sync.RWMutex
	cached authn.Keychain
}

// NewKeyChainProvider returns a new instance for a namespace and a set of
// image pull secrets. If namesapce is not set, or no image pull secret
// references are provided, the default keychain is will be used for further
// requests to get a key chain.
//
// refresh sets how often the cached keychain is rebuilt in the background; a
// non-positive value selects defaultKeychainRefreshInterval. Call Start to warm
// the cache and begin refreshing.
func NewKeyChainProvider(ns string, ips []string, refresh time.Duration) *KeyChainProvider {
	slog.Info("configure authn with image pull secrets",
		"secrets_refs", ips,
		"namespace", ns)

	if refresh <= 0 {
		refresh = defaultKeychainRefreshInterval
	}

	k := &KeyChainProvider{
		namespace:        ns,
		imagePullSecrets: ips,
		refreshInterval:  refresh,
	}
	// Default to the real constructor; tests may override this field.
	k.build = k.buildKeychain

	return k
}

// buildKeychain assembles the keychain from the in-cluster authenticators,
// timing the build so its latency is observable off the request path. The
// returned bool reports whether both in-cluster authenticators were built
// successfully; if either fails it is false. The keychain itself is always
// non-nil: on failure it falls back to whatever could be assembled (at minimum
// the default keychain), which serves the initial cold-start build. A
// background refresh only adopts a build whose bool is true, so a degraded
// rebuild never replaces a good keychain with a default-only one.
func (k *KeyChainProvider) buildKeychain(ctx context.Context) (authn.Keychain, bool) {
	start := time.Now()
	defer func() {
		metrics.KeychainBuildTimer.Observe(time.Since(start).Seconds())
	}()

	var kcs = []authn.Keychain{
		authn.DefaultKeychain,
	}
	ok := true

	// Add the kubernetes authenticator
	if kc, err := kubernetes.NewInCluster(ctx, kubernetes.Options{
		Namespace:        k.namespace,
		ImagePullSecrets: k.imagePullSecrets,
	}); err != nil {
		slog.Error("failed to add kubernetes key chain",
			"error", err)
		ok = false
	} else {
		kcs = append(kcs, kc)
	}

	// Add a "cloud k8s" authenticator
	if kc, err := k8schain.NewInCluster(ctx, k8schain.Options{
		Namespace: k.namespace,
	}); err != nil {
		slog.Error("failed to add k8schain key chain",
			"error", err)
		ok = false
	} else {
		kcs = append(kcs, kc)
	}

	return authn.NewMultiKeychain(kcs...), ok
}

// Start performs one bounded synchronous initial build so the first requests
// are warm, then refreshes the cached keychain on refreshInterval in the
// background until ctx is done. The initial build is best-effort: it is bounded
// by keychainBuildTimeout so a stalled dependency cannot keep the process from
// listening, and its result is cached even if incomplete (KeyChain then serves
// the default keychain until the first successful refresh).
func (k *KeyChainProvider) Start(ctx context.Context) {
	bctx, cancel := context.WithTimeout(ctx, keychainBuildTimeout)
	kc, _ := k.build(bctx)
	cancel()
	k.set(kc)

	t := time.NewTicker(k.refreshInterval)
	go func() {
		defer t.Stop()
		k.refreshLoop(ctx, t.C)
	}()
}

// refreshLoop rebuilds the cached keychain each time tick fires until ctx is
// done. A build is bounded by keychainBuildTimeout. The cache is swapped only
// when the build reports success; a failed or degraded build (e.g. the
// in-cluster authenticators erroring during a transient outage) leaves the
// last-good keychain in place and increments KeychainRefreshFail.
func (k *KeyChainProvider) refreshLoop(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			bctx, cancel := context.WithTimeout(ctx, keychainBuildTimeout)
			kc, ok := k.build(bctx)
			cancel()
			if ok && kc != nil {
				k.set(kc)
				continue
			}
			// Keep the last-good keychain when a refresh fails or is degraded.
			metrics.KeychainRefreshFail.Inc()
			slog.Error("failed to refresh key chain, keeping last-good")
		}
	}
}

func (k *KeyChainProvider) set(kc authn.Keychain) {
	k.mu.Lock()
	k.cached = kc
	k.mu.Unlock()
}

// KeyChain returns the cached keychain from this provider. It performs no
// per-request I/O; the ctx argument is retained for interface compatibility and
// is ignored. Before Start has populated the cache (or if the initial build
// produced nothing), it returns the default keychain, which works for public
// registries.
func (k *KeyChainProvider) KeyChain(_ context.Context) (authn.Keychain, error) {
	k.mu.RLock()
	kc := k.cached
	k.mu.RUnlock()

	if kc == nil {
		return authn.DefaultKeychain, nil
	}

	return kc, nil
}
