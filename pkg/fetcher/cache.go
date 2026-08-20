package fetcher

import (
	"context"
	"errors"
	"fmt"
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
	// serialized holds the bundles in their immutable marshalled form. The
	// cache never stores []*bundle.Bundle: sigstore-go memoizes verification
	// state on the *bundle.Bundle receiver, so handing the same instance to two
	// concurrent verifications is a data race. Each caller unmarshals its own
	// private copy from these bytes.
	serialized [][]byte
	hash       *v1.Hash
	expires    time.Time
}

// flightResult is the singleflight closure's return value: the immutable cache
// entry plus whether the closure was served from a concurrently-populated cache
// entry (fromCache) rather than a fresh upstream fetch. It lets each recipient
// account a hit vs a miss once the source is known.
type flightResult struct {
	entry     cacheEntry
	fromCache bool
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
	// content-addressed, so digest-keying guarantees a moved tag can never
	// substitute a *different image*.
	//
	// That guarantee bounds image identity, not the attestation set: the
	// referrers for a digest are mutable, so a cached positive result can be up
	// to one TTL stale with respect to attestations added or removed for that
	// digest (in particular, attestation-removal-as-revocation is not reflected
	// until the entry expires). Re-verification on a hit re-checks the cached
	// material against the current trust root but does not re-fetch the referrer
	// set; "no attestations" results are not cached (see below), so a
	// newly-published attestation is picked up on the next validation.
	//
	// The digest-only rule must hold in ANY environment, so we gate purely on
	// the reference type and never on tag-naming conventions. Tag references
	// still get singleflight de-duplication below (concurrent-only coalescing is
	// safe regardless of tag mutability); they simply never read from or write
	// to the persisted time cache.
	_, isDigest := ref.(name.Digest)

	// timeCacheable reports whether this call may use the persisted time cache:
	// the cache must be enabled (ttl > 0) and the reference must be a digest.
	timeCacheable := isDigest && c.cacheEnabled

	if timeCacheable {
		if e, ok := c.load(key); ok {
			metrics.BundleCacheHits.Inc()
			// Unmarshal a private copy: sigstore-go memoizes verification state
			// on the *bundle.Bundle receiver, so no two callers may share one.
			bundles, err := deserializeBundles(e.serialized)
			if err != nil {
				return nil, nil, cacheCodecError(err)
			}
			return bundles, e.hash, nil
		}
		// Do not count a miss yet. A concurrent flight may still populate the
		// entry via the second-chance lookup below, in which case this request
		// is really a hit; the hit/miss decision is made once the source of the
		// result is known (see the singleflight result handling further down).
	}

	// If the caller is already cancelled (e.g. a timed-out multi-image
	// Provider.Validate that keeps looping over its remaining keys), do not
	// start a new detached fetch: it would spawn orphaned registry work under
	// the very herd this decorator exists to relieve. A cache hit above is still
	// served because it is free; only a dead request that missed is stopped
	// here, mirroring the mid-flight cancellation handling below.
	if err := ctx.Err(); err != nil {
		return nil, nil, &FetchError{
			Kind:        kindFromContext(err),
			Recoverable: false,
			Err:         err,
		}
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
				return flightResult{entry: e, fromCache: true}, nil
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

		// Cache the immutable serialized form, never []*bundle.Bundle: every
		// recipient below unmarshals its own private copy, so concurrent
		// verifications cannot write memoized state onto a shared *bundle.Bundle.
		ser, err := serializeBundles(b)
		if err != nil {
			return nil, cacheCodecError(err)
		}

		e := cacheEntry{serialized: ser, hash: h, expires: c.now().Add(c.ttl)}
		// Only cache positive results. A digest with no referrers resolves to
		// (nil, nil, nil); caching that would pin "no attestations" for the
		// whole TTL even after one is later published, because the referrer set
		// is mutable even though the digest is immutable. We still return e
		// below so this request reports no attestations, but we do not persist
		// it: the next validation re-fetches and picks up a new attestation.
		if c.cacheEnabled && len(ser) > 0 {
			switch {
			case isDigest:
				c.store(key, e)
			case h != nil:
				// The requested reference is a tag, which is never served from
				// the time cache. The resolved digest, however, is
				// content-addressed, so warm a digest-keyed entry: a later
				// request that arrives *by digest* can then be served. Reads
				// still only happen for digest-input refs above, so this never
				// serves a tag.
				c.store(ref.Context().Digest(h.String()).Name(), e)
			default:
				// Unreachable: len(ser) > 0 implies a resolved digest hash (h is
				// non-nil). Present only to satisfy switch-style linting.
			}
		}
		return flightResult{entry: e, fromCache: false}, nil
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
			// An errored fetch is still an upstream-backed miss (e.g. a
			// registry outage). Count it so failures don't undercount misses
			// and inflate the apparent hit ratio. Gate on timeCacheable to
			// match the success path; cancellations are handled separately and
			// are never counted as a cache outcome.
			if timeCacheable {
				metrics.BundleCacheMisses.Inc()
			}
			return nil, nil, res.Err
		}
		fr, ok := res.Val.(flightResult)
		if !ok {
			return nil, nil, &FetchError{
				Kind:        KindUnknown,
				Recoverable: false,
				Err:         errors.New("bundle cache: unexpected value type"),
			}
		}
		// Now that the source is known, account the outcome: a result served
		// from the (possibly concurrently-populated) time cache is a hit; one
		// backed by a fresh upstream fetch is a miss. Only digest requests
		// consult the time cache, so only they are counted.
		if timeCacheable {
			if fr.fromCache {
				metrics.BundleCacheHits.Inc()
			} else {
				metrics.BundleCacheMisses.Inc()
			}
		}
		// Unmarshal a private copy per caller (see the hit path above).
		bundles, err := deserializeBundles(fr.entry.serialized)
		if err != nil {
			return nil, nil, cacheCodecError(err)
		}
		return bundles, fr.entry.hash, nil
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

// serializeBundles marshals bundles to their immutable JSON form for caching.
// The cache stores bytes rather than *bundle.Bundle so that each caller can be
// given a private, freshly-unmarshalled copy (see deserializeBundles).
func serializeBundles(bundles []*bundle.Bundle) ([][]byte, error) {
	serialized := make([][]byte, len(bundles))
	for i, b := range bundles {
		data, err := b.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("bundle cache: marshalling bundle: %w", err)
		}
		serialized[i] = data
	}
	return serialized, nil
}

// deserializeBundles unmarshals cached bytes into a fresh set of bundles, one
// private instance per caller. sigstore-go memoizes verification state (e.g.
// inclusion-proof/promise flags) on the *bundle.Bundle receiver during
// verification, so callers that verify concurrently must not share instances.
// The round-trip is lossless for verification: all material lives in the proto
// and the memoized flags are recomputed per verification.
func deserializeBundles(serialized [][]byte) ([]*bundle.Bundle, error) {
	bundles := make([]*bundle.Bundle, len(serialized))
	for i, data := range serialized {
		b := &bundle.Bundle{}
		if err := b.UnmarshalJSON(data); err != nil {
			return nil, fmt.Errorf("bundle cache: unmarshalling bundle: %w", err)
		}
		bundles[i] = b
	}
	return bundles, nil
}

// cacheCodecError wraps a bundle (de)serialization failure as a
// non-recoverable FetchError so callers handle it uniformly with other fetch
// failures.
func cacheCodecError(err error) *FetchError {
	return &FetchError{
		Kind:        KindUnknown,
		Recoverable: false,
		Err:         err,
	}
}
