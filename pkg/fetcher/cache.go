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

	// maxEntries bounds the size of the time cache. When it is >0 and the cache
	// is full, storing a new key first evicts the soonest-to-expire entry. 0
	// means unbounded.
	maxEntries int

	// cacheEnabled reports whether the persisted time cache is active (ttl > 0).
	// When false, singleflight still de-duplicates concurrent fetches, but no
	// entries are read, stored, or swept and the janitor does not run.
	cacheEnabled bool

	group singleflight.Group

	mu    sync.RWMutex
	cache map[string]cacheEntry

	// now and stop are here to keep the type testable (injectable clock) and
	// to allow the background janitor to be shut down cleanly.
	now  func() time.Time
	stop chan struct{}
	once sync.Once
}

// NewCachingBundleFetcher wraps inner with a short-TTL, digest-keyed result
// cache (bounded to maxEntries; 0 = unbounded) fronted by singleflight
// de-duplication. Singleflight always runs; a ttl <= 0 disables the persisted
// time cache (and its janitor) while keeping singleflight active. When the time
// cache is enabled a background janitor evicts expired entries every ttl; call
// Stop to release it.
func NewCachingBundleFetcher(inner bundleFetcher, ttl time.Duration, maxEntries int) *CachingBundleFetcher {
	return newCachingBundleFetcher(inner, ttl, maxEntries, time.Now, true)
}

// newCachingBundleFetcher is the test-friendly constructor: it allows injecting
// a clock and skipping the background janitor.
func newCachingBundleFetcher(inner bundleFetcher, ttl time.Duration, maxEntries int, now func() time.Time, runJanitor bool) *CachingBundleFetcher {
	c := &CachingBundleFetcher{
		inner:        inner,
		ttl:          ttl,
		maxEntries:   maxEntries,
		cacheEnabled: ttl > 0,
		cache:        make(map[string]cacheEntry),
		now:          now,
		stop:         make(chan struct{}),
	}
	// Only run the janitor when the time cache is active: nothing is ever stored
	// otherwise, and time.NewTicker panics on a non-positive interval.
	if runJanitor && c.cacheEnabled {
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

	// The persisted time cache is digest-only. OCI tags are mutable: a registry
	// can repoint a tag to a new digest within the TTL window, so serving a tag
	// from a persisted entry could return a verification result for a digest the
	// tag no longer points to -> an admission bypass. Digest references are
	// content-addressed and cannot move, so they are always safe to cache. This
	// property must hold in ANY environment, so we gate purely on the reference
	// type and never on tag-naming conventions. Tag references still get
	// singleflight de-duplication below (concurrent-only coalescing is safe
	// regardless of tag mutability); they simply never read from or write to the
	// persisted time cache.
	_, isDigest := ref.(name.Digest)

	// timeCacheable reports whether this call may use the persisted time cache:
	// the cache must be enabled (ttl > 0) and the reference must be a digest.
	timeCacheable := isDigest && c.cacheEnabled

	if timeCacheable {
		if e, ok := c.load(key); ok {
			metrics.BundleCacheHits.Inc()
			return e.bundles, e.hash, nil
		}
		metrics.BundleCacheMisses.Inc()
	}

	// leader is set (inside the singleflight closure) only for the one call
	// whose closure actually runs. singleflight marks the result Shared for
	// *every* recipient including that leader, so leader lets us attribute a
	// dedupe only to the joiners: an N-caller flight records N-1 dedupes.
	leader := false

	// Singleflight is keyed on the requested reference and always runs,
	// independent of the time cache. For a tag it shares the leader's
	// tag->digest resolution with every joiner in the in-flight window, so a
	// joiner whose tag moved mid-flight receives the leader's digest. That
	// window is bounded by a single fetch and is subsumed by the inherent, much
	// larger admission->kubelet-pull TOCTOU present for ANY mutable-tag
	// admission, so it does not change the security posture in kind. Keeping
	// singleflight on tags is deliberate: collapsing the tag->digest resolve
	// storm is the dominant cost this decorator exists to fix. Use digest
	// references (or registry-enforced tag immutability) for a strong binding.
	ch := c.group.DoChan(key, func() (any, error) {
		leader = true

		// Another caller may have populated the cache while this call queued.
		if timeCacheable {
			if e, ok := c.load(key); ok {
				return e, nil
			}
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
		if c.cacheEnabled {
			switch {
			case isDigest:
				c.store(key, e)
			case h != nil:
				// The requested reference is a tag, which is never served from
				// the time cache. The resolved digest, however, is
				// content-addressed and safe, so warm a digest-keyed entry: a
				// later request that arrives *by digest* can then be served.
				// Reads still only happen for digest-input refs above, so this
				// never serves a tag.
				c.store(ref.Context().Digest(h.String()).Name(), e)
			default:
				// A tag ref that resolved to no attestations (nil hash): there
				// is nothing content-addressed to key on, so nothing is cached.
			}
		}
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
		// Shared is true for every recipient including the leader; only the
		// joiners were actually de-duplicated, so exclude the leader.
		if res.Shared && !leader {
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
	_, exists := c.cache[key]
	evicted := false
	if !exists && c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
		c.evictSoonestToExpireLocked()
		evicted = true
	}
	c.cache[key] = e
	// Publish the gauge while still holding the lock so concurrent mutations
	// update it in the same serialized order in which they mutate the map.
	metrics.BundleCacheEntries.Set(float64(len(c.cache)))
	c.mu.Unlock()

	if evicted {
		metrics.BundleCacheEvictions.Inc()
	}
}

// evictSoonestToExpireLocked removes the entry with the earliest expiry. The
// caller must hold c.mu. Evicting the soonest-to-expire entry is a cheap,
// dependency-free approximation of LRU that keeps the longest-lived entries and
// bounds memory without pulling in a cache library.
func (c *CachingBundleFetcher) evictSoonestToExpireLocked() {
	var (
		victim  string
		soonest time.Time
		found   bool
	)
	for k, e := range c.cache {
		if !found || e.expires.Before(soonest) {
			victim, soonest, found = k, e.expires, true
		}
	}
	if found {
		delete(c.cache, victim)
	}
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
	// Publish the gauge under the lock so it matches the serialized mutation.
	metrics.BundleCacheEntries.Set(float64(n))
	c.mu.Unlock()
	slog.Debug("bundle cache swept", "entries", n)
}
