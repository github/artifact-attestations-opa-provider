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
			name:     "not found status",
			err:      &transport.Error{StatusCode: http.StatusNotFound},
			wantKind: KindNotFound,
			wantCode: http.StatusNotFound,
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

func TestNewFetchErrorClassifiesNotFoundAsNonRecoverable(t *testing.T) {
	fe := newFetchError(StepDescriptor, KindDescriptorError, &transport.Error{StatusCode: http.StatusNotFound})
	assert.Equal(t, KindNotFound, fe.Kind, "404 should classify as not_found, not the descriptor fallback")
	assert.False(t, fe.Recoverable, "404 is deterministic in-request and should not be retried")
	assert.Equal(t, http.StatusNotFound, fe.StatusCode)
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

func TestRetryBundleStopsOnNotFound(t *testing.T) {
	var attempts int

	_, _, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newDescriptorError(&transport.Error{StatusCode: http.StatusNotFound})
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindNotFound, fe.Kind)
	assert.Equal(t, http.StatusNotFound, fe.StatusCode)
	assert.Equal(t, 1, attempts, "a 404 must not be retried")
	assert.Equal(t, 1, fe.Attempts)
}

func TestResolveTransportTimeoutsDerivesFromBudget(t *testing.T) {
	// With no overrides, each phase is a fraction of the per-attempt budget.
	// At a 2.5s budget this reproduces the values this change originally
	// shipped as constants (dial 1.5s, TLS 1.5s, response-header 2s), so the
	// derivation is a generalization of that calibration, not a behavior change
	// for the deploying environment.
	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(2500 * time.Millisecond)
	assert.Equal(t, 1500*time.Millisecond, dial)
	assert.Equal(t, 1500*time.Millisecond, tlsHandshake)
	assert.Equal(t, 2000*time.Millisecond, responseHeader)

	// Every derived phase must stay strictly under the budget so a stall is
	// abandoned before the attempt's context deadline.
	assert.Less(t, dial, 2500*time.Millisecond)
	assert.Less(t, tlsHandshake, 2500*time.Millisecond)
	assert.Less(t, responseHeader, 2500*time.Millisecond)
}

func TestResolveTransportTimeoutsHonorsOverrides(t *testing.T) {
	defer restoreTransportOverrides(DialTimeoutOverride, TLSHandshakeTimeoutOverride, ResponseHeaderTimeoutOverride)

	DialTimeoutOverride = 400 * time.Millisecond
	TLSHandshakeTimeoutOverride = 0 // still derived
	ResponseHeaderTimeoutOverride = 900 * time.Millisecond

	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(2 * time.Second)
	assert.Equal(t, 400*time.Millisecond, dial, "positive override used verbatim")
	assert.Equal(t, 1200*time.Millisecond, tlsHandshake, "zero override derives from budget")
	assert.Equal(t, 900*time.Millisecond, responseHeader, "positive override used verbatim")
}

func TestResolveTransportTimeoutsFloorsSmallBudget(t *testing.T) {
	// For a modestly small budget the floor keeps phase timeouts off sub-100ms
	// values that would trip on normal latency, while still staying under the
	// budget. At 300ms every phase (0.6/0.6/0.8 -> 180/180/240ms) is floored to
	// 250ms, which remains < 300ms.
	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(300 * time.Millisecond)
	assert.Equal(t, minPhaseTimeout, dial)
	assert.Equal(t, minPhaseTimeout, tlsHandshake)
	assert.Equal(t, minPhaseTimeout, responseHeader)
	assert.Less(t, dial, 300*time.Millisecond)
}

func TestResolveTransportTimeoutsKeepsPhasesBelowTinyBudget(t *testing.T) {
	// For a pathologically small budget the floor would meet or exceed the
	// attempt budget, so the hard invariant wins: each phase falls back to its
	// fractional value and stays strictly below the budget (a phase timeout at
	// or above the attempt deadline could never fire first).
	const budget = 100 * time.Millisecond
	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(budget)
	assert.Equal(t, 60*time.Millisecond, dial)
	assert.Equal(t, 60*time.Millisecond, tlsHandshake)
	assert.Equal(t, 80*time.Millisecond, responseHeader)
	assert.Less(t, dial, budget)
	assert.Less(t, tlsHandshake, budget)
	assert.Less(t, responseHeader, budget)
}

func TestNewRegistryDialerUsesResolvedTimeout(t *testing.T) {
	// The dialer must carry the resolved dial timeout (the transport's
	// DialContext closure hides it, so this is where dial-timeout regressions
	// are caught).
	d := newRegistryDialer(1234 * time.Millisecond)
	assert.Equal(t, 1234*time.Millisecond, d.Timeout)
	assert.Equal(t, 30*time.Second, d.KeepAlive)
}

func TestRegistryTransportDialContextEnforcesDialTimeout(t *testing.T) {
	defer restoreTransportOverrides(DialTimeoutOverride, TLSHandshakeTimeoutOverride, ResponseHeaderTimeoutOverride)
	DialTimeoutOverride = 150 * time.Millisecond
	tr := newRegistryTransport()

	// 192.0.2.1 is TEST-NET-1 (RFC 5737): reserved and unrouted, so a dial is
	// dropped and blocks until the dial timeout fires rather than getting a
	// fast connection-refused. This exercises the transport's DialContext
	// end-to-end and would block far past the assertion window if the dialer
	// reverted to go-containerregistry's stock 30s default.
	start := time.Now()
	conn, err := tr.DialContext(context.Background(), "tcp", "192.0.2.1:80")
	elapsed := time.Since(start)
	if conn != nil {
		conn.Close()
	}

	require.Error(t, err)
	assert.Less(t, elapsed, 5*time.Second, "dial must abort at ~DialTimeout, not the stock 30s")
}

func TestNewRegistryTransportUsesResolvedTimeouts(t *testing.T) {
	defer restoreTransportOverrides(DialTimeoutOverride, TLSHandshakeTimeoutOverride, ResponseHeaderTimeoutOverride)
	DialTimeoutOverride, TLSHandshakeTimeoutOverride, ResponseHeaderTimeoutOverride = 0, 0, 0

	tr := newRegistryTransport()

	_, wantTLS, wantResponseHeader := resolveTransportTimeouts(Timeout)
	assert.Equal(t, wantTLS, tr.TLSHandshakeTimeout)
	assert.Equal(t, wantResponseHeader, tr.ResponseHeaderTimeout)

	// Cloning the default transport must preserve its connection-pool tuning
	// rather than resetting to the net/http zero values.
	assert.Equal(t, 100, tr.MaxIdleConns)
	assert.Equal(t, 50, tr.MaxIdleConnsPerHost)
	assert.True(t, tr.ForceAttemptHTTP2)
	require.NotNil(t, tr.DialContext)
}

func TestConfigureTransportRebuildsForCurrentTimeout(t *testing.T) {
	originalTimeout := Timeout
	originalTransport := registryTransport
	defer func() {
		Timeout = originalTimeout
		registryTransport = originalTransport
	}()

	Timeout = 4 * time.Second
	ConfigureTransport()

	_, wantTLS, wantResponseHeader := resolveTransportTimeouts(4 * time.Second)
	require.NotNil(t, registryTransport)
	assert.Equal(t, wantTLS, registryTransport.TLSHandshakeTimeout)
	assert.Equal(t, wantResponseHeader, registryTransport.ResponseHeaderTimeout)
}

func TestGetRemoteOptionsIncludesTunedTransport(t *testing.T) {
	// GetRemoteOptions must reuse the shared, tuned transport singleton so the
	// connection pool is shared across requests. remote.Option is an opaque
	// closure, so the transport can't be read back out; assert the option count
	// instead, which regresses if remote.WithTransport(registryTransport) is
	// dropped from the list.
	require.NotNil(t, registryTransport)
	opts := GetRemoteOptions(nil)
	assert.Len(t, opts, 3)
}

func restoreTransportOverrides(dial, tlsHandshake, responseHeader time.Duration) {
	DialTimeoutOverride = dial
	TLSHandshakeTimeoutOverride = tlsHandshake
	ResponseHeaderTimeoutOverride = responseHeader
}
