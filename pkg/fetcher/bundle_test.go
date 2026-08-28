package fetcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryBundleTimesOutEachAttempt(t *testing.T) {
	const maxAttempts = 3
	var attempts int

	result, err := retryBundle(t.Context(), maxAttempts, 5*time.Millisecond, 0, func(ctx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, maxAttempts, result.Attempts)
}

func TestRetryBundleReturnsSuccessfulAttempt(t *testing.T) {
	expectedBundles := []*bundle.Bundle{{}}
	expectedHash := &v1.Hash{Algorithm: "sha256", Hex: "abc"}
	var attempts int

	result, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		if attempts < 3 {
			return nil, nil, errors.New("temporary failure")
		}
		return expectedBundles, expectedHash, nil
	})

	require.NoError(t, err)
	assert.Equal(t, attempts, result.Attempts)
	assert.Same(t, expectedBundles[0], result.Bundles[0])
	assert.Same(t, expectedHash, result.Hash)
}

func TestRetryBundleStopsWhenParentIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var attempts int

	result, err := retryBundle(ctx, 3, time.Second, time.Second, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		cancel()
		return nil, nil, errors.New("temporary failure")
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, result.Attempts, attempts)
}

func TestRetryBundleReturnsLastError(t *testing.T) {
	firstErr := errors.New("first failure")
	lastErr := errors.New("last failure")
	attempts := 0

	result, err := retryBundle(t.Context(), 2, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		if attempts == 1 {
			return nil, nil, firstErr
		}
		return nil, nil, lastErr
	})

	require.ErrorIs(t, err, lastErr)
	require.NotErrorIs(t, err, firstErr)
	assert.Equal(t, attempts, result.Attempts)
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
	assert.False(t, fe.Recoverable, "429 is not cleared by in-line retry within our budget; fail fast")

	// TooManyRequests diagnostic-code branch (status code not populated).
	fe = newFetchError(StepDescriptor, KindDescriptorError, &transport.Error{
		Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode}},
	})
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.False(t, fe.Recoverable, "429 is not cleared by in-line retry within our budget; fail fast")
}

func TestRetryBundleFailsFastOnThrottle(t *testing.T) {
	var attempts int

	result, err := retryBundle(t.Context(), 3, time.Second, time.Second, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newBlobError(&transport.Error{StatusCode: http.StatusTooManyRequests})
	})

	assert.Equal(t, 1, attempts, "a 429 must fail fast, not retry in-line")

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.Equal(t, 1, fe.Attempts)
	assert.Equal(t, fe.Attempts, result.Attempts)
}

func TestNewFetchErrorRetriesThrottlingWhenEnabled(t *testing.T) {
	t.Cleanup(func() { RetryThrottled = false })
	RetryThrottled = true

	fe := newFetchError(StepReferrers, KindReferrersUnavailable, &transport.Error{StatusCode: http.StatusTooManyRequests})
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.True(t, fe.Recoverable, "with -bundle-retry-throttled a 429 is recoverable again")
}

func TestRetryBundleRetriesThrottleWhenEnabled(t *testing.T) {
	t.Cleanup(func() { RetryThrottled = false })
	RetryThrottled = true

	const maxAttempts = 3
	var attempts int

	result, err := retryBundle(t.Context(), maxAttempts, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newBlobError(&transport.Error{StatusCode: http.StatusTooManyRequests})
	})

	assert.Equal(t, maxAttempts, attempts, "with retry-throttled enabled a 429 retries like other recoverable errors")

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindThrottled, fe.Kind)
	assert.Equal(t, maxAttempts, fe.Attempts)
	assert.Equal(t, result.Attempts, attempts)
}

func TestRetryBundlePreservesStepOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	_, err := retryBundle(ctx, 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
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

	_, err := retryBundle(t.Context(), maxAttempts, 5*time.Millisecond, 0, func(ctx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
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

	result, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, &FetchError{Step: StepDescriptor, Kind: KindUnauthorized, Recoverable: false, Err: errors.New("401")}
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindUnauthorized, fe.Kind)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 1, fe.Attempts)
}

func TestRetryBundleStopsOnNotFound(t *testing.T) {
	var attempts int

	result, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newDescriptorError(&transport.Error{StatusCode: http.StatusNotFound})
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindNotFound, fe.Kind)
	assert.Equal(t, http.StatusNotFound, fe.StatusCode)
	assert.Equal(t, 1, result.Attempts, "a 404 must not be retried")
	assert.Equal(t, 1, fe.Attempts)
}

func TestRetryBundleTrailDeMasksTerminalCancellation(t *testing.T) {
	// Two establishment stalls (recoverable timeout on the descriptor GET),
	// then the parent context is canceled partway through the third attempt.
	// The terminal reason stays the honest "canceled", but the trail must
	// preserve the two prior timeouts that reason alone would mask.
	ctx, cancel := context.WithCancel(t.Context())
	var attempts int

	_, _, err := retryBundle(ctx, 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		if attempts < 3 {
			return nil, nil, newDescriptorError(context.DeadlineExceeded)
		}
		cancel()
		return nil, nil, newDescriptorError(context.Canceled)
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindCanceled, fe.Kind, "terminal reason stays the true final state")
	assert.Equal(t, StepDescriptor, fe.Step)
	assert.Equal(t, 3, fe.Attempts)
	require.Len(t, fe.Trail, 3)
	assert.Equal(t, AttemptOutcome{Reason: KindTimeout, Step: StepDescriptor}, fe.Trail[0])
	assert.Equal(t, AttemptOutcome{Reason: KindTimeout, Step: StepDescriptor}, fe.Trail[1])
	assert.Equal(t, AttemptOutcome{Reason: KindCanceled, Step: StepDescriptor}, fe.Trail[2])
	assert.Equal(t, "timeout:descriptor,timeout:descriptor,canceled:descriptor", AttemptTrail(err))
	assert.Len(t, fe.Trail, fe.Attempts, "len(Trail) == Attempts")
}

func TestRetryBundleTrailRecordsExhaustedRetries(t *testing.T) {
	const maxAttempts = 3

	_, _, err := retryBundle(t.Context(), maxAttempts, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		return nil, nil, newReferrersError(errors.New("boom"))
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindReferrersUnavailable, fe.Kind, "terminal reason is the last attempt's reason")
	assert.Equal(t, maxAttempts, fe.Attempts)
	require.Len(t, fe.Trail, maxAttempts)
	for i, o := range fe.Trail {
		assert.Equal(t, AttemptOutcome{Reason: KindReferrersUnavailable, Step: StepReferrers}, o, "attempt %d", i)
	}
	assert.Len(t, fe.Trail, fe.Attempts, "len(Trail) == Attempts")
}

func TestRetryBundleTrailStopsOnNonRecoverable(t *testing.T) {
	var attempts int

	_, _, err := retryBundle(t.Context(), 3, time.Second, 0, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newFetchError(StepDescriptor, KindDescriptorError, &transport.Error{StatusCode: http.StatusUnauthorized})
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, 1, attempts, "a non-recoverable error must not be retried")
	assert.Equal(t, KindUnauthorized, fe.Kind)
	require.Len(t, fe.Trail, 1)
	assert.Equal(t, AttemptOutcome{Reason: KindUnauthorized, Step: StepDescriptor}, fe.Trail[0])
	assert.Equal(t, "unauthorized:descriptor", AttemptTrail(err))
	assert.Len(t, fe.Trail, fe.Attempts, "len(Trail) == Attempts")
}

func TestRetryBundleTrailCarriesPriorAttemptsOnDelayCancel(t *testing.T) {
	// Drive the delay-branch cancel deterministically instead of racing a
	// wall-clock timer: retryBundle emits its per-attempt debug log immediately
	// before the inter-attempt delay select, so a handler that cancels the
	// parent on that log guarantees the next select observes cancellation. The
	// handler runs synchronously in retryBundle's own goroutine, so there is no
	// timing dependency. The terminal error is the delay-branch cancel (no
	// in-flight step) but must still carry the first attempt's outcome.
	ctx, cancel := context.WithCancel(t.Context())
	prev := slog.Default()
	slog.SetDefault(slog.New(&cancelOnMessage{msg: "bundle fetch attempt failed", cancel: cancel}))
	defer slog.SetDefault(prev)

	var attempts int
	// A long delay so the select can only return via the (already canceled)
	// parent, never the timer; if the debug hook ever stops firing the test
	// fails fast on assertions rather than hanging on the timer.
	_, _, err := retryBundle(ctx, 3, time.Second, 5*time.Second, func(context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		attempts++
		return nil, nil, newDescriptorError(context.DeadlineExceeded)
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, 1, attempts, "cancel during the delay must stop before a second attempt")
	assert.Equal(t, KindCanceled, fe.Kind)
	assert.Empty(t, fe.Step, "the delay-branch cancel has no in-flight step")
	assert.Equal(t, 1, fe.Attempts)
	require.Len(t, fe.Trail, 1)
	assert.Equal(t, AttemptOutcome{Reason: KindTimeout, Step: StepDescriptor}, fe.Trail[0])
	assert.Equal(t, "timeout:descriptor", AttemptTrail(err))
	assert.Len(t, fe.Trail, fe.Attempts, "len(Trail) == Attempts")
}

func TestRetryBundleTrailClassifiesNonFetchErrors(t *testing.T) {
	// An attempt may return a raw (non-*FetchError) error, e.g. ctx.Err()
	// directly. The trail must classify it the same way the terminal error is
	// classified rather than recording it as "unknown".
	const maxAttempts = 3

	_, _, err := retryBundle(t.Context(), maxAttempts, 5*time.Millisecond, 0, func(ctx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	})

	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, KindTimeout, fe.Kind, "terminal reason is classified from the raw error")
	require.Len(t, fe.Trail, maxAttempts)
	for i, o := range fe.Trail {
		assert.Equal(t, KindTimeout, o.Reason, "attempt %d trail must match the terminal reason, not unknown", i)
		assert.Empty(t, o.Step, "a raw attempt error carries no fetch step")
	}
	// A stepless outcome renders as just its reason (no trailing separator).
	assert.Equal(t, "timeout,timeout,timeout", AttemptTrail(err))
	assert.Len(t, fe.Trail, fe.Attempts, "len(Trail) == Attempts")
}

func TestAttemptTrail(t *testing.T) {
	// A non-*FetchError carries no trail.
	assert.Empty(t, AttemptTrail(errors.New("boom")))
	// A *FetchError with no recorded trail renders empty.
	assert.Empty(t, AttemptTrail(&FetchError{Kind: KindCanceled}))

	// Outcomes render as ordered "reason:step" tokens, oldest first.
	fe := &FetchError{Trail: []AttemptOutcome{
		{Reason: KindTimeout, Step: StepDescriptor},
		{Reason: KindCanceled, Step: StepReferrers},
	}}
	assert.Equal(t, "timeout:descriptor,canceled:referrers", AttemptTrail(fe))
	// A wrapped *FetchError is still rendered.
	assert.Equal(t, "timeout:descriptor,canceled:referrers", AttemptTrail(fmt.Errorf("wrapped: %w", fe)))

	// A missing reason falls back to "unknown" so the token is never bare.
	assert.Equal(t, "unknown:blob", AttemptTrail(&FetchError{Trail: []AttemptOutcome{{Step: StepBlob}}}))

	// A stepless outcome renders as just its reason, with no trailing separator.
	assert.Equal(t, "timeout,canceled", AttemptTrail(&FetchError{Trail: []AttemptOutcome{
		{Reason: KindTimeout},
		{Reason: KindCanceled},
	}}))
}

// cancelOnMessage is a slog.Handler that invokes cancel whenever it sees a
// record with the given message. retryBundle logs each retryable attempt
// failure immediately before the inter-attempt delay select, so canceling from
// this handler deterministically steers the loop into the delay-branch cancel
// path without depending on wall-clock timing. Handle runs synchronously in the
// caller's goroutine.
type cancelOnMessage struct {
	msg    string
	cancel context.CancelFunc
}

func (*cancelOnMessage) Enabled(context.Context, slog.Level) bool { return true }

func (h *cancelOnMessage) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.cancel()
	}
	return nil
}

func (h *cancelOnMessage) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *cancelOnMessage) WithGroup(string) slog.Handler { return h }

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

func TestResolveTransportTimeoutsAppliesHardFloorBelowBudget(t *testing.T) {
	// For a pathologically small budget the 250ms floor intentionally wins even
	// though it exceeds the budget: we keep a usable dial/handshake floor rather
	// than derive an unusable sub-10ms timeout. The attempt context simply fires
	// first in this already-broken configuration.
	const budget = 100 * time.Millisecond
	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(budget)
	assert.Equal(t, minPhaseTimeout, dial)
	assert.Equal(t, minPhaseTimeout, tlsHandshake)
	assert.Equal(t, minPhaseTimeout, responseHeader)
	assert.Greater(t, dial, budget, "the floor is kept even when it exceeds the budget")
}

func TestNewRegistryDialerUsesResolvedTimeout(t *testing.T) {
	// The dialer must carry the resolved dial timeout (the transport's
	// DialContext closure hides it, so this is where dial-timeout regressions
	// are caught).
	d := newRegistryDialer(1234 * time.Millisecond)
	assert.Equal(t, 1234*time.Millisecond, d.Timeout)
	assert.Equal(t, DialKeepAlive, d.KeepAlive, "dialer must carry the configured keep-alive, not a hardcoded value")
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

	// The transport must carry the tuned idle-pool lifetime and sizes (the
	// package-var defaults), overriding go-containerregistry's inherited
	// 90s / 100 / 50. Wiring of non-default values is covered separately by
	// TestNewRegistryTransportAppliesPoolTuning.
	assert.Equal(t, 10*time.Second, tr.IdleConnTimeout)
	assert.Equal(t, 25, tr.MaxIdleConns)
	assert.Equal(t, 25, tr.MaxIdleConnsPerHost)

	// Cloning the default transport must preserve its remaining tuning rather
	// than resetting to the net/http zero values.
	assert.True(t, tr.ForceAttemptHTTP2)
	require.NotNil(t, tr.DialContext)
}

func TestNewRegistryTransportAppliesPoolTuning(t *testing.T) {
	// Non-default values must flow through to the transport, proving the pool
	// fields are wired from the package vars rather than hardcoded.
	origIdle, origMax, origMaxPer := IdleConnTimeout, MaxIdleConns, MaxIdleConnsPerHost
	t.Cleanup(func() {
		IdleConnTimeout, MaxIdleConns, MaxIdleConnsPerHost = origIdle, origMax, origMaxPer
	})
	IdleConnTimeout = 11 * time.Second
	MaxIdleConns = 13
	MaxIdleConnsPerHost = 9

	tr := newRegistryTransport()
	assert.Equal(t, 11*time.Second, tr.IdleConnTimeout)
	assert.Equal(t, 13, tr.MaxIdleConns)
	assert.Equal(t, 9, tr.MaxIdleConnsPerHost)
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

// TestDoBundleFromNameSharesAuthHandshake stands up a fake bearer registry and
// proves that a single DoBundleFromName fetch performs the registry auth
// handshake (GET /v2/ ping + token exchange) exactly once, even though it makes
// three top-level go-containerregistry calls (Get, Referrers, Image) against the
// same repository. Without remote.Reuse(puller) each call mints its own throwaway
// puller and the ping/token counts are 3/3 instead of 1/1.
func TestDoBundleFromNameSharesAuthHandshake(t *testing.T) {
	const bundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	bundleBlob, err := os.ReadFile("testdata/valid-bundle.json")
	require.NoError(t, err)

	// The attestation's single layer is the bundle JSON blob, addressed by its
	// own digest.
	layerHash, layerSize, err := v1.SHA256(bytes.NewReader(bundleBlob))
	require.NoError(t, err)

	// A throwaway empty-config descriptor. The config blob is never fetched on
	// this path (we only read layers[0]), so it need not be served.
	emptyHash, _, err := v1.SHA256(bytes.NewReader([]byte("{}")))
	require.NoError(t, err)
	emptyConfig := v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: emptyHash, Size: 2}

	// Attestation manifest referencing the bundle layer.
	attBytes, err := json.Marshal(v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  bundleArtifactType,
		Config:        emptyConfig,
		Layers: []v1.Descriptor{{
			MediaType: bundleArtifactType,
			Digest:    layerHash,
			Size:      layerSize,
		}},
	})
	require.NoError(t, err)
	attHash, _, err := v1.SHA256(bytes.NewReader(attBytes))
	require.NoError(t, err)

	// Referrers index pointing at the attestation manifest, carrying the
	// sigstore bundle artifactType that DoBundleFromName filters on.
	referrersBytes, err := json.Marshal(v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []v1.Descriptor{{
			MediaType:    types.OCIManifestSchema1,
			Digest:       attHash,
			Size:         int64(len(attBytes)),
			ArtifactType: bundleArtifactType,
		}},
	})
	require.NoError(t, err)

	// Subject image manifest, fetched by tag.
	subjectBytes, err := json.Marshal(v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config:        emptyConfig,
		Layers:        []v1.Descriptor{},
	})
	require.NoError(t, err)
	subjectHash, _, err := v1.SHA256(bytes.NewReader(subjectBytes))
	require.NoError(t, err)

	var pingCount, tokenCount atomic.Int64
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			// Auth ping: challenge the client for a bearer token. Counting this
			// is the whole point of the test — it must fire once per fetch.
			pingCount.Add(1)
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm=%q,service="registry"`, server.URL+"/token"))
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/token":
			tokenCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"test-token","access_token":"test-token"}`))
		case r.URL.Path == "/v2/test/app/manifests/latest":
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Docker-Content-Digest", subjectHash.String())
			_, _ = w.Write(subjectBytes)
		case r.URL.Path == "/v2/test/app/manifests/"+attHash.String():
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
			w.Header().Set("Docker-Content-Digest", attHash.String())
			_, _ = w.Write(attBytes)
		case strings.HasPrefix(r.URL.Path, "/v2/test/app/referrers/"):
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			_, _ = w.Write(referrersBytes)
		case r.URL.Path == "/v2/test/app/blobs/"+layerHash.String():
			_, _ = w.Write(bundleBlob)
		default:
			t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ref, err := name.ParseReference(
		strings.TrimPrefix(server.URL, "http://")+"/test/app:latest",
		name.Insecure,
	)
	require.NoError(t, err)

	ro := []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithTransport(http.DefaultTransport),
	}

	bundles, hash, err := DoBundleFromName(t.Context(), ref, ro)
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	require.NotNil(t, hash)
	assert.Equal(t, subjectHash, *hash)

	assert.Equal(t, int64(1), pingCount.Load(),
		"auth ping should run once per fetch, not once per remote.* call")
	assert.Equal(t, int64(1), tokenCount.Load(),
		"token exchange should run once per fetch, not once per remote.* call")
}
