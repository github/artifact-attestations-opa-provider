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

func TestRetryBundleStopsOnNonRecoverableError(t *testing.T) {
	expectedErr := &NonRecoverableError{Op: "decode", Err: errors.New("invalid bundle")}
	var attempts int

	_, _, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, expectedErr
	})

	require.ErrorIs(t, err, expectedErr)
	assert.Equal(t, 1, attempts)
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

func TestIsAuthenticationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "unauthorized status",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized},
			want: true,
		},
		{
			name: "forbidden status",
			err:  &transport.Error{StatusCode: http.StatusForbidden},
			want: true,
		},
		{
			name: "unauthorized diagnostic",
			err: &transport.Error{Errors: []transport.Diagnostic{
				{Code: transport.UnauthorizedErrorCode},
			}},
			want: true,
		},
		{
			name: "denied diagnostic",
			err: &transport.Error{Errors: []transport.Diagnostic{
				{Code: transport.DeniedErrorCode},
			}},
			want: true,
		},
		{
			name: "wrapped authentication error",
			err:  fmt.Errorf("remote get: %w", &transport.Error{StatusCode: http.StatusUnauthorized}),
			want: true,
		},
		{
			name: "server error",
			err:  &transport.Error{StatusCode: http.StatusInternalServerError},
		},
		{
			name: "ordinary error",
			err:  errors.New("connection reset"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isAuthenticationError(test.err))
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
