package authn

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
)

// stubKeychain is a minimal authn.Keychain that gives each build a distinct,
// identifiable instance without touching a real cluster.
type stubKeychain struct{ id int }

func (*stubKeychain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

func keychainID(t *testing.T, kc authn.Keychain) int {
	t.Helper()
	sk, ok := kc.(*stubKeychain)
	require.Truef(t, ok, "expected a *stubKeychain, got %T", kc)
	return sk.id
}

// countingBuilder returns a build func that hands out a fresh *stubKeychain on
// each call (id 1, 2, 3, …), always reporting success, plus a counter of how
// many times it has run.
func countingBuilder() (func(context.Context) (authn.Keychain, bool), *atomic.Int64) {
	var n atomic.Int64
	build := func(_ context.Context) (authn.Keychain, bool) {
		return &stubKeychain{id: int(n.Add(1))}, true
	}
	return build, &n
}

// TestNewKeyChainProviderRefreshInterval verifies the constructor clamps a
// non-positive interval to the default and wires the real builder.
func TestNewKeyChainProviderRefreshInterval(t *testing.T) {
	assert.Equal(t, defaultKeychainRefreshInterval,
		NewKeyChainProvider("", nil, 0).refreshInterval)
	assert.Equal(t, defaultKeychainRefreshInterval,
		NewKeyChainProvider("", nil, -time.Second).refreshInterval)
	assert.Equal(t, 90*time.Second,
		NewKeyChainProvider("", nil, 90*time.Second).refreshInterval)

	assert.NotNil(t, NewKeyChainProvider("", nil, time.Minute).build,
		"constructor must wire the default builder")
}

// TestKeyChainBeforeStartReturnsDefault verifies the pre-Start safety net:
// before the cache is populated, the default keychain is served.
func TestKeyChainBeforeStartReturnsDefault(t *testing.T) {
	k := NewKeyChainProvider("ns", []string{"secret"}, time.Minute)

	kc, err := k.KeyChain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, authn.DefaultKeychain, kc)
}

// TestKeyChainBuiltOnceAndCached verifies Start builds exactly once and that
// reads are served from the cache with no per-request rebuild.
func TestKeyChainBuiltOnceAndCached(t *testing.T) {
	build, n := countingBuilder()
	// A long interval keeps the background ticker from firing during the test.
	k := &KeyChainProvider{refreshInterval: time.Hour, build: build}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k.Start(ctx)

	require.Equal(t, int64(1), n.Load(), "Start should build the keychain exactly once")

	first, err := k.KeyChain(ctx)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		kc, err := k.KeyChain(ctx)
		require.NoError(t, err)
		assert.Same(t, first, kc, "every read should return the cached instance")
	}
	assert.Equal(t, int64(1), n.Load(), "KeyChain must not rebuild on each request")
}

// TestKeyChainRefreshSwapsCached verifies a background refresh replaces the
// cached keychain with the newly built instance.
func TestKeyChainRefreshSwapsCached(t *testing.T) {
	build, n := countingBuilder()
	k := &KeyChainProvider{refreshInterval: time.Hour, build: build}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Warm the cache (id 1), then drive the refresh loop with a manual tick so
	// the test doesn't depend on wall-clock timing.
	warm, _ := k.build(ctx)
	k.set(warm)
	require.Equal(t, int64(1), n.Load())
	first, err := k.KeyChain(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, keychainID(t, first))

	tick := make(chan time.Time)
	go k.refreshLoop(ctx, tick)

	tick <- time.Time{}
	require.Eventually(t, func() bool {
		kc, _ := k.KeyChain(ctx)
		return keychainID(t, kc) == 2
	}, time.Second, time.Millisecond, "refresh should swap in the newly built keychain")
	assert.Equal(t, int64(2), n.Load())
}

// TestKeyChainRefreshKeepsLastGoodOnFailure verifies a refresh whose build
// reports failure leaves the previous good instance in place and increments the
// failure metric, even when the build returns a (degraded) non-nil keychain —
// the production case where the in-cluster authenticators error but
// buildKeychain still returns a default-only MultiKeychain.
func TestKeyChainRefreshKeepsLastGoodOnFailure(t *testing.T) {
	var n atomic.Int64
	build := func(_ context.Context) (authn.Keychain, bool) {
		id := n.Add(1)
		if id == 2 {
			// A degraded rebuild: non-nil, but the authenticators failed.
			return &stubKeychain{id: -1}, false
		}
		return &stubKeychain{id: int(id)}, true
	}
	k := &KeyChainProvider{refreshInterval: time.Hour, build: build}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	warm, _ := k.build(ctx) // id 1
	k.set(warm)
	first, err := k.KeyChain(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, keychainID(t, first))

	failBefore := testutil.ToFloat64(metrics.KeychainRefreshFail)

	tick := make(chan time.Time)
	go k.refreshLoop(ctx, tick)

	tick <- time.Time{}
	require.Eventually(t, func() bool { return n.Load() == 2 }, time.Second, time.Millisecond,
		"the failing refresh build should have run")

	kc, err := k.KeyChain(ctx)
	require.NoError(t, err)
	assert.Same(t, first, kc, "a failed (ok=false) refresh must not replace the last-good keychain")
	assert.Equal(t, 1, keychainID(t, kc))

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.KeychainRefreshFail)-failBefore >= 1
	}, time.Second, time.Millisecond, "a failed refresh should increment KeychainRefreshFail")
}

// TestStartInitialBuildIsBounded verifies the synchronous initial build runs
// under a deadline-bound context so a stalled dependency cannot keep the
// process from starting to listen.
func TestStartInitialBuildIsBounded(t *testing.T) {
	var hadDeadline atomic.Bool
	build := func(ctx context.Context) (authn.Keychain, bool) {
		_, ok := ctx.Deadline()
		hadDeadline.Store(ok)
		return &stubKeychain{id: 1}, true
	}
	// A parent context without its own deadline, so any deadline the build sees
	// must have been added by Start.
	k := &KeyChainProvider{refreshInterval: time.Hour, build: build}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k.Start(ctx)

	assert.True(t, hadDeadline.Load(),
		"the initial build must run under a bounded context")
}
