package fetcher

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFetcher is a controllable bundleFetcher for exercising the cache.
type fakeFetcher struct {
	calls   int32
	block   chan struct{} // when non-nil, BundleFromName blocks until closed
	err     error
	bundles []*bundle.Bundle
	hash    *v1.Hash
}

func (f *fakeFetcher) BundleFromName(ctx context.Context, _ name.Reference, _ []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	atomic.AddInt32(&f.calls, 1)
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
	return f.bundles, f.hash, nil
}

func (*fakeFetcher) GetRemoteOptions(_ authn.Keychain) []remote.Option { return nil }

func (f *fakeFetcher) callCount() int32 { return atomic.LoadInt32(&f.calls) }

func mustRef(t *testing.T, s string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(s)
	require.NoError(t, err)
	return ref
}

func TestCacheServesRepeatFetches(t *testing.T) {
	hash := &v1.Hash{Algorithm: "sha256", Hex: "abc"}
	inner := &fakeFetcher{bundles: []*bundle.Bundle{{}}, hash: hash}
	c := newCachingBundleFetcher(inner, time.Minute, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1")

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
	c := newCachingBundleFetcher(inner, 100*time.Millisecond, now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1")

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

func TestSingleflightDedupsConcurrentFetches(t *testing.T) {
	inner := &fakeFetcher{block: make(chan struct{}), bundles: []*bundle.Bundle{{}}, hash: &v1.Hash{Hex: "abc"}}
	c := newCachingBundleFetcher(inner, time.Minute, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1")

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

	assert.Equal(t, int32(1), inner.callCount(), "a burst of concurrent fetches collapses to one")
	for _, err := range errs {
		assert.NoError(t, err)
	}
}

func TestErrorsAreNotCached(t *testing.T) {
	inner := &fakeFetcher{err: errors.New("boom")}
	c := newCachingBundleFetcher(inner, time.Minute, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1")

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
	c := newCachingBundleFetcher(inner, time.Minute, time.Now, false)
	ref := mustRef(t, "ghcr.io/o/r:v1")

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
	c := newCachingBundleFetcher(inner, time.Minute, time.Now, false)

	_, _, err := c.BundleFromName(context.Background(), mustRef(t, "ghcr.io/o/r:v1"), nil)
	require.NoError(t, err)
	_, _, err = c.BundleFromName(context.Background(), mustRef(t, "ghcr.io/o/r:v2"), nil)
	require.NoError(t, err)

	assert.Equal(t, int32(2), inner.callCount(), "different references are fetched independently")
}

func TestStopIsIdempotent(t *testing.T) {
	c := NewCachingBundleFetcher(&fakeFetcher{}, time.Minute)
	c.Stop()
	assert.NotPanics(t, c.Stop)
}
