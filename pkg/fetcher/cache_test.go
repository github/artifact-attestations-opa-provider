package fetcher

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
)

// fakeFetcher is a controllable bundleFetcher for exercising the cache.
type fakeFetcher struct {
	calls   int32
	block   chan struct{} // when non-nil, BundleFromName blocks until closed
	err     error
	bundles []*bundle.Bundle
	hash    *v1.Hash
	// hashes, when non-empty, is returned by successive calls (indexed by call
	// number) instead of hash. This lets a test simulate a mutable tag whose
	// resolved digest changes between calls.
	hashes []*v1.Hash
}

func (f *fakeFetcher) BundleFromName(ctx context.Context, _ name.Reference, _ []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	n := atomic.AddInt32(&f.calls, 1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, nil, f.err
	}
	h := f.hash
	if len(f.hashes) > 0 {
		idx := int(n - 1)
		if idx >= len(f.hashes) {
			idx = len(f.hashes) - 1
		}
		h = f.hashes[idx]
	}
	return f.bundles, h, nil
}

func (*fakeFetcher) GetRemoteOptions(_ authn.Keychain) []remote.Option { return nil }

func (f *fakeFetcher) callCount() int32 { return atomic.LoadInt32(&f.calls) }

func mustRef(t *testing.T, s string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(s)
	require.NoError(t, err)
	return ref
}

// mustDigestRef builds a valid, immutable digest reference, using a 64-character
// sha256 hex made by repeating hexChar. Only digest refs are served from the
// time cache, so cache-hit tests must use these.
func mustDigestRef(t *testing.T, hexChar string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference("ghcr.io/o/r@sha256:" + strings.Repeat(hexChar, 64))
	require.NoError(t, err)
	return ref
}

func TestCacheServesRepeatFetches(t *testing.T) {
	hash := &v1.Hash{Algorithm: "sha256", Hex: "abc"}
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: hash}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	// Digest ref: only content-addressed references are served from the cache.
	ref := mustDigestRef(t, "a")

	for i := 0; i < 3; i++ {
		b, h, err := c.BundleFromName(context.Background(), ref, nil)
		require.NoError(t, err)
		assert.Len(t, b, 1)
		assert.Equal(t, hash, h)
	}

	assert.Equal(t, int32(1), inner.callCount(), "only the first fetch should reach the registry")
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	c := newCachingBundleFetcher(inner, 100*time.Millisecond, 0, now, false)
	ref := mustDigestRef(t, "a")

	_, _, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	_, _, err = c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), inner.callCount(), "second call within TTL is a cache hit")

	mu.Lock()
	clock = clock.Add(200 * time.Millisecond)
	mu.Unlock()

	_, _, err = c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), inner.callCount(), "call after TTL expiry re-fetches")
}

func TestDigestRefServedFromCacheWithinTTL(t *testing.T) {
	hash := &v1.Hash{Algorithm: "sha256", Hex: "abc"}
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: hash}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	ref := mustDigestRef(t, "d")

	b1, h1, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	b2, h2, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(1), inner.callCount(), "a digest ref is served from the time cache within the TTL")
	assert.Equal(t, hash, h1)
	assert.Equal(t, hash, h2)
	assert.Len(t, b1, 1)
	assert.Len(t, b2, 1)

	_, ok := c.load(ref.Name())
	assert.True(t, ok, "the digest ref is persisted in the time cache")
}

func TestTagRefNotServedFromTimeCache(t *testing.T) {
	hashA := &v1.Hash{Algorithm: "sha256", Hex: "aaa"}
	hashB := &v1.Hash{Algorithm: "sha256", Hex: "bbb"}
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hashes: []*v1.Hash{hashA, hashB}}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1") // a mutable tag

	_, h1, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.Equal(t, hashA, h1)

	// The tag has been repointed to a new digest. A second call within the TTL
	// must re-fetch (tag refs are never served from the time cache) and observe
	// the new digest, never a stale cached result.
	_, h2, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(2), inner.callCount(), "a tag ref is re-fetched, never served from the time cache")
	assert.Equal(t, hashB, h2, "the second call reflects the moved tag, not a stale entry")

	// The tag itself is never persisted under its own key.
	_, ok := c.load(ref.Name())
	assert.False(t, ok, "a tag ref is not stored in the time cache under its tag key")
}

func TestConcurrentTagRefsSingleflightedToOneFetch(t *testing.T) {
	inner := &fakeFetcher{block: make(chan struct{}), bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1") // a tag

	beforeDeduped := testutil.ToFloat64(metrics.BundleFetchDeduped)

	const n = 25
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Go(func() {
			_, _, errs[i] = c.BundleFromName(context.Background(), ref, nil)
		})
	}

	// Wait for the single in-flight fetch to start, then let the rest attach.
	require.Eventually(t, func() bool { return inner.callCount() >= 1 }, time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	close(inner.block)
	wg.Wait()

	// Even though tag refs are never time-cached, a concurrent burst of the same
	// tag still collapses to a single upstream fetch via singleflight.
	assert.Equal(t, int32(1), inner.callCount(), "a burst of concurrent tag fetches collapses to one")
	for _, err := range errs {
		require.NoError(t, err)
	}

	// singleflight marks the result Shared for every recipient including the
	// leader, but only the N-1 joiners were actually de-duplicated.
	afterDeduped := testutil.ToFloat64(metrics.BundleFetchDeduped)
	assert.InDelta(t, float64(n-1), afterDeduped-beforeDeduped, 1e-9, "an N-caller flight records N-1 dedupes")
}

func TestSingleflightRunsWithTimeCacheDisabled(t *testing.T) {
	inner := &fakeFetcher{block: make(chan struct{}), bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	// ttl=0 disables the persisted time cache; singleflight must still run.
	c := newCachingBundleFetcher(inner, 0, 0, time.Now, false)
	// Even a digest ref is not time-cached when the cache is disabled.
	ref := mustDigestRef(t, "a")

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Go(func() {
			_, _, errs[i] = c.BundleFromName(context.Background(), ref, nil)
		})
	}

	require.Eventually(t, func() bool { return inner.callCount() >= 1 }, time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	close(inner.block)
	wg.Wait()

	assert.Equal(t, int32(1), inner.callCount(), "concurrent fetches collapse to one even with the time cache disabled")
	for _, err := range errs {
		assert.NoError(t, err)
	}
}

func TestTimeCacheDisabledDigestNotServed(t *testing.T) {
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	c := newCachingBundleFetcher(inner, 0, 0, time.Now, false)
	ref := mustDigestRef(t, "a")

	_, _, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	_, _, err = c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(2), inner.callCount(), "with the time cache disabled, a repeat digest fetch is not served from cache")
	_, ok := c.load(ref.Name())
	assert.False(t, ok, "nothing is stored when the time cache is disabled")
}

func TestNewWithZeroTTLDoesNotStartJanitor(t *testing.T) {
	// ttl=0 must not start the janitor: time.NewTicker panics on a
	// non-positive interval, and there is nothing to sweep.
	c := NewCachingBundleFetcher(&fakeFetcher{}, 0, 0)
	assert.NotPanics(t, c.Stop)
}

func TestErrorsAreNotCached(t *testing.T) {
	inner := &fakeFetcher{err: errors.New("boom")}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	ref := mustDigestRef(t, "a")

	_, _, err := c.BundleFromName(context.Background(), ref, nil)
	require.Error(t, err)
	_, _, err = c.BundleFromName(context.Background(), ref, nil)
	require.Error(t, err)

	assert.Equal(t, int32(2), inner.callCount(), "failed fetches are not cached and are retried")
	_, ok := c.load(ref.Name())
	assert.False(t, ok)
}

func TestCallerCancellationStillWarmsCache(t *testing.T) {
	hash := &v1.Hash{Hex: "abc"}
	inner := &fakeFetcher{block: make(chan struct{}), bundles: []*bundle.Bundle{{}}, hash: hash}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)
	ref := mustDigestRef(t, "a")

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.BundleFromName(ctx, ref, nil)
		errc <- err
	}()

	// Once the (detached) shared fetch is running, the caller gives up.
	require.Eventually(t, func() bool { return inner.callCount() == 1 }, time.Second, time.Millisecond)
	cancel()

	err := <-errc
	require.Error(t, err)
	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindCanceled, fe.Kind)

	// The shared fetch keeps running; once it completes it warms the cache.
	close(inner.block)
	require.Eventually(t, func() bool { _, ok := c.load(ref.Name()); return ok }, time.Second, time.Millisecond)

	b, h, err := c.BundleFromName(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.Len(t, b, 1)
	assert.Equal(t, hash, h)
	assert.Equal(t, int32(1), inner.callCount(), "the warmed cache serves the later caller without a new fetch")
}

func TestDistinctRefsFetchedSeparately(t *testing.T) {
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	c := newCachingBundleFetcher(inner, time.Minute, 0, time.Now, false)

	_, _, err := c.BundleFromName(context.Background(), mustDigestRef(t, "a"), nil)
	require.NoError(t, err)
	_, _, err = c.BundleFromName(context.Background(), mustDigestRef(t, "b"), nil)
	require.NoError(t, err)

	assert.Equal(t, int32(2), inner.callCount(), "different references are fetched independently")
}

func TestMaxEntriesEviction(t *testing.T) {
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "x"}}
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	c := newCachingBundleFetcher(inner, time.Hour, 2, now, false)

	before := testutil.ToFloat64(metrics.BundleCacheEvictions)

	// Store three distinct digest refs, advancing the clock between each so the
	// first-inserted entry has the earliest expiry and is the eviction victim.
	refs := []name.Reference{
		mustDigestRef(t, "a"),
		mustDigestRef(t, "b"),
		mustDigestRef(t, "c"),
	}
	for _, ref := range refs {
		_, _, err := c.BundleFromName(context.Background(), ref, nil)
		require.NoError(t, err)
		mu.Lock()
		clock = clock.Add(time.Second)
		mu.Unlock()
	}

	c.mu.RLock()
	n := len(c.cache)
	_, hasFirst := c.cache[refs[0].Name()]
	_, hasLast := c.cache[refs[2].Name()]
	c.mu.RUnlock()

	assert.Equal(t, 2, n, "the cache is bounded to maxEntries")
	assert.False(t, hasFirst, "the soonest-to-expire entry (first inserted) is evicted")
	assert.True(t, hasLast, "the most recently inserted entry is retained")

	after := testutil.ToFloat64(metrics.BundleCacheEvictions)
	assert.InDelta(t, 1.0, after-before, 1e-9, "exactly one eviction was recorded")
}

func TestStopIsIdempotent(t *testing.T) {
	c := NewCachingBundleFetcher(&fakeFetcher{}, time.Minute, 0)
	c.Stop()
	assert.NotPanics(t, c.Stop)
}
