package fetcher

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"golang.org/x/sync/singleflight"

	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
)

// bundleFetcher is the behavior CachingBundleFetcher decorates. It matches the
// provider's BundleFetcher interface so a CachingBundleFetcher can be dropped in
// wherever a DefaultBundleFetcher is used.
type bundleFetcher interface {
	BundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error)
	GetRemoteOptions(kc authn.Keychain) []remote.Option
}

type cacheEntry struct {
	bundles []*bundle.Bundle
	hash    *v1.Hash
	expires time.Time
}

// CachingBundleFetcher decorates a bundle fetcher with a short-TTL result cache
// and singleflight de-duplication.
//
// Admission bursts (e.g. a workload rolling out across many clusters at once)
// produce many concurrent validations for the *same* image. Without this
// decorator each one makes its own OCI round-trip, and that concurrent load is
// what overwhelms the registry and pushes fetches past the admission timeout.
//
// The cache serves repeat validations of a stable digest from memory, and
// singleflight collapses a burst of concurrent identical fetches into a single
// upstream request whose result is shared with every waiter.
type CachingBundleFetcher struct {
	inner bundleFetcher
	ttl   time.Duration

	group singleflight.Group

	mu    sync.RWMutex
	cache map[string]cacheEntry

	// now and stop are here to keep the type testable (injectable clock) and
	// to allow the background janitor to be shut down cleanly.
	now  func() time.Time
	stop chan struct{}
	once sync.Once
}

// NewCachingBundleFetcher wraps inner with a cache whose entries live for ttl.
// A background janitor evicts expired entries every ttl. Call Stop to release it.
func NewCachingBundleFetcher(inner bundleFetcher, ttl time.Duration) *CachingBundleFetcher {
	return newCachingBundleFetcher(inner, ttl, time.Now, true)
}

// newCachingBundleFetcher is the test-friendly constructor: it allows injecting
// a clock and skipping the background janitor.
func newCachingBundleFetcher(inner bundleFetcher, ttl time.Duration, now func() time.Time, runJanitor bool) *CachingBundleFetcher {
	c := &CachingBundleFetcher{
		inner: inner,
		ttl:   ttl,
		cache: make(map[string]cacheEntry),
		now:   now,
		stop:  make(chan struct{}),
	}
	if runJanitor {
		go c.janitor(ttl)
	}
	return c
}

// GetRemoteOptions delegates to the wrapped fetcher.
func (c *CachingBundleFetcher) GetRemoteOptions(kc authn.Keychain) []remote.Option {
	return c.inner.GetRemoteOptions(kc)
}

// BundleFromName returns the bundles for ref, serving them from the cache when
// possible and otherwise de-duplicating concurrent fetches for the same ref.
func (c *CachingBundleFetcher) BundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	key := ref.Name()

	if e, ok := c.load(key); ok {
		metrics.BundleCacheHits.Inc()
		return e.bundles, e.hash, nil
	}
	metrics.BundleCacheMisses.Inc()

	ch := c.group.DoChan(key, func() (any, error) {
		// Another caller may have populated the cache while this call queued.
		if e, ok := c.load(key); ok {
			return e, nil
		}

		// Detach from the triggering caller's cancellation so the shared fetch
		// can run to completion and warm the cache even if that caller's
		// admission request is already cancelled. The inner fetcher bounds the
		// work with its own per-attempt timeout and retry budget.
		fctx := context.WithoutCancel(ctx)

		b, h, err := c.inner.BundleFromName(fctx, ref, ro)
		if err != nil {
			// Do not cache failures: the next request should retry.
			return nil, err
		}

		e := cacheEntry{bundles: b, hash: h, expires: c.now().Add(c.ttl)}
		c.store(key, e)
		return e, nil
	})

	select {
	case <-ctx.Done():
		// This caller gave up (typically the admission timeout). The shared
		// fetch above keeps running and may still populate the cache for
		// subsequent callers.
		return nil, nil, &FetchError{
			Kind:        kindFromContext(ctx.Err()),
			Recoverable: false,
			Err:         ctx.Err(),
		}
	case res := <-ch:
		if res.Shared {
			metrics.BundleFetchDeduped.Inc()
		}
		if res.Err != nil {
			return nil, nil, res.Err
		}
		e, ok := res.Val.(cacheEntry)
		if !ok {
			return nil, nil, &FetchError{
				Kind:        KindUnknown,
				Recoverable: false,
				Err:         errors.New("bundle cache: unexpected value type"),
			}
		}
		return e.bundles, e.hash, nil
	}
}

// Stop shuts down the background janitor. It is safe to call more than once.
func (c *CachingBundleFetcher) Stop() {
	c.once.Do(func() { close(c.stop) })
}

func (c *CachingBundleFetcher) load(key string) (cacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.cache[key]
	c.mu.RUnlock()
	if !ok || !c.now().Before(e.expires) {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *CachingBundleFetcher) store(key string, e cacheEntry) {
	c.mu.Lock()
	c.cache[key] = e
	n := len(c.cache)
	c.mu.Unlock()
	metrics.BundleCacheEntries.Set(float64(n))
}

func (c *CachingBundleFetcher) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *CachingBundleFetcher) sweep() {
	now := c.now()
	c.mu.Lock()
	for k, e := range c.cache {
		if !now.Before(e.expires) {
			delete(c.cache, k)
		}
	}
	n := len(c.cache)
	c.mu.Unlock()
	metrics.BundleCacheEntries.Set(float64(n))
	slog.Debug("bundle cache swept", "entries", n)
}
