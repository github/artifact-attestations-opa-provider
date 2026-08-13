package fetcher

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryBundleTimesOutEachAttempt(t *testing.T) {
	const maxAttempts = 3
	var attempts int

	_, _, err := retryBundle(t.Context(), maxAttempts, 5*time.Millisecond, 0, func(ctx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, maxAttempts, attempts)
}

func TestRetryBundleReturnsSuccessfulAttempt(t *testing.T) {
	expectedBundles := []*bundle.Bundle{{}}
	expectedHash := &v1.Hash{Algorithm: "sha256", Hex: "abc"}
	var attempts int

	bundles, hash, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		if attempts < 3 {
			return nil, nil, errors.New("temporary failure")
		}
		return expectedBundles, expectedHash, nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.Same(t, expectedBundles[0], bundles[0])
	assert.Same(t, expectedHash, hash)
}

func TestRetryBundleStopsWhenParentIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var attempts int

	_, _, err := retryBundle(ctx, 3, time.Second, time.Second, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		cancel()
		return nil, nil, errors.New("temporary failure")
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, attempts)
}

func TestRetryBundleReturnsLastError(t *testing.T) {
	firstErr := errors.New("first failure")
	lastErr := errors.New("last failure")
	attempts := 0

	_, _, err := retryBundle(t.Context(), 2, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		if attempts == 1 {
			return nil, nil, firstErr
		}
		return nil, nil, lastErr
	})

	require.ErrorIs(t, err, lastErr)
	assert.NotErrorIs(t, err, firstErr)
}

func TestClassifyTransport(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantKind FailureKind
		wantCode int
	}{
		{
			name:     "unauthorized status",
			err:      &transport.Error{StatusCode: http.StatusUnauthorized},
			wantKind: KindUnauthorized,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "forbidden status",
			err:      &transport.Error{StatusCode: http.StatusForbidden},
			wantKind: KindForbidden,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "too many requests status",
			err:      &transport.Error{StatusCode: http.StatusTooManyRequests},
			wantKind: KindThrottled,
			wantCode: http.StatusTooManyRequests,
		},
		{
			name: "unauthorized diagnostic",
			err: &transport.Error{Errors: []transport.Diagnostic{
				{Code: transport.UnauthorizedErrorCode},
			}},
			wantKind: KindUnauthorized,
		},
		{
			name: "denied diagnostic",
			err: &transport.Error{Errors: []transport.Diagnostic{
				{Code: transport.DeniedErrorCode},
			}},
			wantKind: KindForbidden,
		},
		{
			name: "too many requests diagnostic",
			err: &transport.Error{Errors: []transport.Diagnostic{
				{Code: transport.TooManyRequestsErrorCode},
			}},
			wantKind: KindThrottled,
		},
		{
			name:     "wrapped authentication error",
			err:      fmt.Errorf("remote get: %w", &transport.Error{StatusCode: http.StatusUnauthorized}),
			wantKind: KindUnauthorized,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "server error is not auth",
			err:      &transport.Error{StatusCode: http.StatusInternalServerError},
			wantKind: KindUnknown,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "deadline exceeded",
			err:      context.DeadlineExceeded,
			wantKind: KindTimeout,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			wantKind: KindCanceled,
		},
		{
			name:     "ordinary error",
			err:      errors.New("connection reset"),
			wantKind: KindUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, code := classifyTransport(test.err)
			assert.Equal(t, test.wantKind, kind)
			assert.Equal(t, test.wantCode, code)
		})
	}
}

func TestClassify(t *testing.T) {
	fe := &FetchError{Step: StepReferrers, Kind: KindReferrersUnavailable, Attempts: 3}
	reason, step, attempts := Classify(fe)
	assert.Equal(t, "referrers_unavailable", reason)
	assert.Equal(t, "referrers", step)
	assert.Equal(t, 3, attempts)

	reason, step, attempts = Classify(errors.New("some other error"))
	assert.Equal(t, "unknown", reason)
	assert.Empty(t, step)
	assert.Equal(t, 0, attempts)

	reason, _, _ = Classify(fmt.Errorf("wrapped: %w", &FetchError{Kind: KindTimeout}))
	assert.Equal(t, "timeout", reason)
}

func TestFetchErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("boom")
	fe := &FetchError{Step: StepBlob, Kind: KindBlobError, Attempts: 2, StatusCode: 500, Err: inner}

	assert.Contains(t, fe.Error(), "step=blob")
	assert.Contains(t, fe.Error(), "reason=blob_error")
	assert.ErrorIs(t, fe, inner)
}

func TestNewFetchErrorClassifiesAuthAsNonRecoverable(t *testing.T) {
	fe := newFetchError(StepDescriptor, KindDescriptorError, &transport.Error{StatusCode: http.StatusForbidden})
	assert.Equal(t, KindForbidden, fe.Kind)
	assert.False(t, fe.Recoverable)
	assert.Equal(t, http.StatusForbidden, fe.StatusCode)

	fe = newFetchError(StepBlob, KindBlobError, errors.New("connection reset"))
	assert.Equal(t, KindBlobError, fe.Kind)
	assert.True(t, fe.Recoverable)
}

func TestNewFetchErrorClassifiesThrottling(t *testing.T) {
	// HTTP 429 status-code branch.
	fe := newFetchError(StepReferrers, KindReferrersUnavailable, &transport.Error{StatusCode: http.StatusTooManyRequests})
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.Equal(t, http.StatusTooManyRequests, fe.StatusCode)
	assert.True(t, fe.Recoverable, "throttling should be retried")

	// TooManyRequests diagnostic-code branch (status code not populated).
	fe = newFetchError(StepDescriptor, KindDescriptorError, &transport.Error{
		Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode}},
	})
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.True(t, fe.Recoverable, "throttling should be retried")
}

func TestRetryBundlePreservesStepOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	_, _, err := retryBundle(ctx, 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		cancel()
		return nil, nil, newReferrersError(errors.New("boom"))
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindCanceled, fe.Kind)
	assert.Equal(t, StepReferrers, fe.Step, "cancellation error should preserve the in-flight step")
}

func TestRetryBundleTimeoutSetsAttemptsAndReason(t *testing.T) {
	const maxAttempts = 3

	_, _, err := retryBundle(t.Context(), maxAttempts, 5*time.Millisecond, 0, func(ctx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		<-ctx.Done()
		return nil, nil, newFetchError(StepDescriptor, KindDescriptorError, ctx.Err())
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindTimeout, fe.Kind)
	assert.Equal(t, maxAttempts, fe.Attempts)
}

func TestRetryBundleStopsOnNonRecoverableFetchError(t *testing.T) {
	var attempts int

	_, _, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, &FetchError{Step: StepDescriptor, Kind: KindUnauthorized, Recoverable: false, Err: errors.New("401")}
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindUnauthorized, fe.Kind)
	assert.Equal(t, 1, attempts)
	assert.Equal(t, 1, fe.Attempts)
}

func TestSelectBundleDescriptors(t *testing.T) {
	const (
		bundleV03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
		bundleV02 = "application/vnd.dev.sigstore.bundle.v0.2+json"
		other     = "application/vnd.oci.image.manifest.v1+json"
		provV1    = "https://slsa.dev/provenance/v1"
		sbom      = "https://spdx.dev/Document"
	)

	desc := func(artifactType, predicate, hex string) v1.Descriptor {
		d := v1.Descriptor{
			ArtifactType: artifactType,
			Digest:       v1.Hash{Algorithm: "sha256", Hex: hex},
		}
		if predicate != "" {
			d.Annotations = map[string]string{PredicateTypeAnnotation: predicate}
		}
		return d
	}

	tests := []struct {
		name          string
		manifests     []v1.Descriptor
		predicateType string
		want          []string
	}{
		{
			name: "empty predicate returns all sigstore bundles and skips others",
			manifests: []v1.Descriptor{
				desc(bundleV03, provV1, "aaa"),
				desc(other, provV1, "bbb"),
				desc(bundleV02, "", "ccc"),
			},
			predicateType: "",
			want:          []string{"aaa", "ccc"},
		},
		{
			name: "predicate returns only the first matching referrer",
			manifests: []v1.Descriptor{
				desc(bundleV03, sbom, "aaa"),
				desc(bundleV03, provV1, "bbb"),
				desc(bundleV03, provV1, "ccc"),
			},
			predicateType: provV1,
			want:          []string{"bbb"},
		},
		{
			name: "predicate with no match returns nothing",
			manifests: []v1.Descriptor{
				desc(bundleV03, sbom, "aaa"),
				desc(bundleV03, "https://example.com/custom/v1", "bbb"),
			},
			predicateType: provV1,
			want:          nil,
		},
		{
			name: "predicate skips non-sigstore referrers with matching annotation",
			manifests: []v1.Descriptor{
				desc(other, provV1, "aaa"),
				desc(bundleV03, provV1, "bbb"),
			},
			predicateType: provV1,
			want:          []string{"bbb"},
		},
		{
			name: "predicate skips sigstore bundles missing the annotation",
			manifests: []v1.Descriptor{
				desc(bundleV03, "", "aaa"),
				desc(bundleV03, provV1, "bbb"),
			},
			predicateType: provV1,
			want:          []string{"bbb"},
		},
		{
			name:          "no manifests returns nothing",
			manifests:     nil,
			predicateType: provV1,
			want:          nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selectBundleDescriptors(test.manifests, test.predicateType)

			var hexes []string
			for _, d := range got {
				hexes = append(hexes, d.Digest.Hex)
			}
			assert.Equal(t, test.want, hexes)
		})
	}
}
