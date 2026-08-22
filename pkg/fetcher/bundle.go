package fetcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

var (
	// UserAgentString to use when accessing remote OCI registries.
	UserAgentString = fmt.Sprintf("artifact-attestations-opa-provider/%s (%s; %s)",
		"dev",
		runtime.GOOS,
		runtime.GOARCH)
	// MaxAttempts is the number of attempts when fetching a bundle.
	MaxAttempts = 3
	// Timeout for a single attempt to fetch a bundle.
	Timeout = time.Second * 3
	// Delay between attempts to fetch bundles.
	Delay = time.Duration(0)
	// DialTimeoutOverride, TLSHandshakeTimeoutOverride, and
	// ResponseHeaderTimeoutOverride optionally pin the corresponding registry
	// connection-phase timeout. Zero (the default) means "derive from Timeout"
	// via resolveTransportTimeouts; a positive value is used verbatim. They let
	// an operator with an unusual registry or forward proxy override a single
	// phase without restating the whole per-attempt budget.
	DialTimeoutOverride           = time.Duration(0)
	TLSHandshakeTimeoutOverride   = time.Duration(0)
	ResponseHeaderTimeoutOverride = time.Duration(0)
)

// Registry connection-phase timeouts are a decomposition of the per-attempt
// fetch budget (Timeout), not independently chosen constants: go-containerregistry's
// stock transport uses a 30s dial and 10s TLS-handshake timeout — both longer
// than a typical fetch attempt — so a request routed (via the registry's global
// endpoint) to a degraded geo-replica can burn the whole deadline in connection
// setup and be cancelled without ever retrying against a healthy replica. Each
// phase is instead bounded below Timeout so a stall is abandoned early, leaving
// parent (gatekeeper / admission-webhook) budget for retryBundle to open a
// fresh connection. Deriving from Timeout keeps the provider correct by default
// at any -bundle-timeout rather than baking in values tuned for one deployment.
const (
	// dialTimeoutFraction and tlsHandshakeTimeoutFraction bound the two
	// sequential phases of connection establishment; responseHeaderTimeoutFraction
	// bounds the wait for the first response byte after the request is written.
	dialTimeoutFraction           = 0.6
	tlsHandshakeTimeoutFraction   = 0.6
	responseHeaderTimeoutFraction = 0.8
	// minPhaseTimeout floors every derived phase so a very small -bundle-timeout
	// cannot produce sub-100ms timeouts that trip on normal network latency.
	minPhaseTimeout = 250 * time.Millisecond
)

// registryTransport is the shared HTTP transport used for all registry access.
// It is created once so the underlying connection pool is reused across
// requests (creating a transport per request would defeat pooling). It is
// rebuilt by ConfigureTransport once flags are parsed; until then it reflects
// the default Timeout.
var registryTransport = newRegistryTransport()

// ConfigureTransport rebuilds the shared registry transport from the current
// Timeout and phase overrides. Call it once at startup after Timeout and the
// *Override vars are set (e.g. from flags). It reassigns a package-level var and
// is not safe to call concurrently with in-flight registry fetches.
func ConfigureTransport() {
	registryTransport = newRegistryTransport()
}

// resolveTransportTimeouts returns the effective dial, TLS-handshake, and
// response-header timeouts for a per-attempt budget of bundleTimeout. A positive
// *Override is honored verbatim; a zero override derives that phase as a
// fraction of bundleTimeout, floored at minPhaseTimeout.
func resolveTransportTimeouts(bundleTimeout time.Duration) (dial, tlsHandshake, responseHeader time.Duration) {
	dial = pickPhaseTimeout(DialTimeoutOverride, bundleTimeout, dialTimeoutFraction)
	tlsHandshake = pickPhaseTimeout(TLSHandshakeTimeoutOverride, bundleTimeout, tlsHandshakeTimeoutFraction)
	responseHeader = pickPhaseTimeout(ResponseHeaderTimeoutOverride, bundleTimeout, responseHeaderTimeoutFraction)
	return
}

// pickPhaseTimeout returns override when positive, otherwise fraction*bundleTimeout
// floored at minPhaseTimeout.
func pickPhaseTimeout(override, bundleTimeout time.Duration, fraction float64) time.Duration {
	if override > 0 {
		return override
	}
	if derived := time.Duration(float64(bundleTimeout) * fraction); derived > minPhaseTimeout {
		return derived
	}
	return minPhaseTimeout
}

// newRegistryTransport returns an http.Transport based on go-containerregistry's
// DefaultTransport but with the connection-establishment timeouts resolved from
// the current per-attempt budget (see resolveTransportTimeouts). Cloning the
// default preserves the other tuned fields (idle-connection pool sizes, HTTP/2,
// proxy) while overriding only the timeouts.
func newRegistryTransport() *http.Transport {
	dial, tlsHandshake, responseHeader := resolveTransportTimeouts(Timeout)
	t := remote.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{
		Timeout:   dial,
		KeepAlive: 30 * time.Second,
	}).DialContext
	t.TLSHandshakeTimeout = tlsHandshake
	t.ResponseHeaderTimeout = responseHeader
	return t
}

// FailureKind is a stable, low-cardinality classification of why a bundle
// fetch failed. It is safe to use as a metric label value and a log field.
type FailureKind string

const (
	// KindTimeout indicates an attempt exceeded its timeout / the context
	// deadline was exceeded.
	KindTimeout FailureKind = "timeout"
	// KindCanceled indicates the parent context was canceled.
	KindCanceled FailureKind = "canceled"
	// KindUnauthorized indicates the registry returned HTTP 401.
	KindUnauthorized FailureKind = "unauthorized"
	// KindForbidden indicates the registry returned HTTP 403 / denied.
	KindForbidden FailureKind = "forbidden"
	// KindThrottled indicates the registry returned HTTP 429 (rate limited).
	KindThrottled FailureKind = "throttled"
	// KindNotFound indicates the registry returned HTTP 404 (manifest/blob
	// not found). It is deterministic within a single admission request, so
	// it is treated as non-recoverable.
	KindNotFound FailureKind = "not_found"
	// KindReferrersUnavailable indicates the OCI Referrers API call failed.
	KindReferrersUnavailable FailureKind = "referrers_unavailable"
	// KindDescriptorError indicates the image manifest (descriptor) GET failed.
	KindDescriptorError FailureKind = "descriptor_error"
	// KindBlobError indicates fetching a referrer image / blob failed.
	KindBlobError FailureKind = "blob_error"
	// KindBundleInvalid indicates a fetched bundle could not be decoded.
	KindBundleInvalid FailureKind = "bundle_invalid"
	// KindUnknown is the fallback when the error could not be classified.
	KindUnknown FailureKind = "unknown"
)

// Step identifies which stage of the OCI bundle fetch failed.
type Step string

const (
	// StepDescriptor is the initial image manifest (descriptor) GET.
	StepDescriptor Step = "descriptor"
	// StepReferrers is the OCI Referrers API lookup.
	StepReferrers Step = "referrers"
	// StepBlob is fetching a referrer image / reading its layer.
	StepBlob Step = "blob"
	// StepDecode is unmarshalling the bundle JSON.
	StepDecode Step = "decode"
)

// FetchError is a structured error describing a failed attempt to fetch a
// bundle from an OCI registry. It records which Step failed, a stable failure
// Kind, how many attempts were made, and (when known) the HTTP StatusCode, so
// callers can log, categorize, and emit metrics without parsing error strings.
type FetchError struct {
	Step        Step
	Kind        FailureKind
	Attempts    int
	StatusCode  int
	Recoverable bool
	Err         error
}

func (e *FetchError) Error() string {
	return fmt.Sprintf("error fetching bundle: step=%s reason=%s attempts=%d status=%d: %v",
		e.Step, e.Kind, e.Attempts, e.StatusCode, e.Err)
}

func (e *FetchError) Unwrap() error {
	return e.Err
}

// DefaultBundleFetcher is the default implementation of the BundleFetcher.
type DefaultBundleFetcher struct{}

// BundleFromName fetches a sigstore bundle for a container from the OCI
// registry.
func (*DefaultBundleFetcher) BundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	return BundleFromName(ctx, ref, ro)
}

// GetRemoteOptions returns the options to provide when accessing remote.
func (*DefaultBundleFetcher) GetRemoteOptions(kc authn.Keychain) []remote.Option {
	return GetRemoteOptions(kc)
}

// BundleFromName fetches a sigstore bundle for a container from
// a registry with retry.
func BundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	return retryBundle(ctx, MaxAttempts, Timeout, Delay, func(attemptCtx context.Context) ([]*bundle.Bundle, *v1.Hash, error) {
		return DoBundleFromName(attemptCtx, ref, ro)
	})
}

type bundleAttempt func(context.Context) ([]*bundle.Bundle, *v1.Hash, error)

func retryBundle(ctx context.Context, maxAttempts int, timeout, delay time.Duration, attempt bundleAttempt) ([]*bundle.Bundle, *v1.Hash, error) {
	var lastErr error
	var attempts int

	for i := 0; i < maxAttempts; i++ {
		if i > 0 && delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, nil, &FetchError{
					Kind:        kindFromContext(ctx.Err()),
					Attempts:    attempts,
					Recoverable: false,
					Err:         ctx.Err(),
				}
			case <-t.C:
				// we are ready to proceed with next
				// attempt
			}
		}

		attempts = i + 1
		ictx, cancel := context.WithTimeout(ctx, timeout)
		b, h, err := attempt(ictx)
		cancel()
		if err == nil {
			return b, h, nil
		}
		lastErr = err

		// Stop early on errors that a retry cannot fix (auth, invalid
		// bundle). Record how many attempts we made for observability.
		var fe *FetchError
		if errors.As(err, &fe) && !fe.Recoverable {
			fe.Attempts = attempts
			return nil, nil, fe
		}
		if cerr := ctx.Err(); cerr != nil {
			// Preserve the step from the in-flight attempt (if any) so
			// cancellation failures still report where they occurred.
			var step Step
			if fe != nil {
				step = fe.Step
			}
			return nil, nil, &FetchError{
				Step:        step,
				Kind:        kindFromContext(cerr),
				Attempts:    attempts,
				Recoverable: false,
				Err:         cerr,
			}
		}

		// Log each retryable attempt failure at debug level so an operator
		// can dig into the individual failures behind a retried fetch.
		reason, step, _ := Classify(err)
		slog.Debug("bundle fetch attempt failed",
			"attempt", attempts,
			"max_attempts", maxAttempts,
			"reason", reason,
			"step", step,
			"error", err)
	}

	return nil, nil, finalizeFetchError(lastErr, attempts)
}

// DoBundleFromName fetches a sigstore bundle for a container from
// a registry.
func DoBundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	var opts []remote.Option

	opts = append(opts, ro...)
	opts = append(opts, remote.WithContext(ctx))

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, nil, newDescriptorError(err)
	}

	digest := ref.Context().Digest(desc.Digest.String())
	referrers, err := remote.Referrers(digest, opts...)
	if err != nil {
		return nil, nil, newReferrersError(err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, newReferrersError(err)
	}

	bundles := make([]*bundle.Bundle, 0)

	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), opts...)
		if err != nil {
			return nil, nil, newBlobError(err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return nil, nil, newBlobError(err)
		}
		layer0, err := layers[0].Uncompressed()
		if err != nil {
			return nil, nil, newBlobError(err)
		}
		bundleBytes, err := io.ReadAll(layer0)
		layer0.Close()
		if err != nil {
			return nil, nil, newBlobError(err)
		}
		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, &FetchError{
				Step:        StepDecode,
				Kind:        KindBundleInvalid,
				Recoverable: false,
				Err:         err,
			}
		}
		bundles = append(bundles, b)
	}

	if len(bundles) == 0 {
		return nil, nil, nil
	}

	return bundles, &desc.Digest, nil
}

// newFetchError builds a FetchError for a failed fetch step. It derives the
// failure Kind (and HTTP status, when available) from the underlying error,
// falling back to the supplied kind for unclassified errors. Authentication
// failures and invalid bundles are marked non-recoverable so retries stop.
func newFetchError(step Step, fallback FailureKind, err error) *FetchError {
	kind, code := classifyTransport(err)
	if kind == KindUnknown {
		kind = fallback
	}
	recoverable := kind != KindUnauthorized &&
		kind != KindForbidden &&
		kind != KindBundleInvalid &&
		kind != KindNotFound
	return &FetchError{
		Step:        step,
		Kind:        kind,
		StatusCode:  code,
		Recoverable: recoverable,
		Err:         err,
	}
}

// newDescriptorError builds a FetchError for a failed image manifest GET.
func newDescriptorError(err error) *FetchError {
	return newFetchError(StepDescriptor, KindDescriptorError, err)
}

// newReferrersError builds a FetchError for a failed OCI Referrers API call.
func newReferrersError(err error) *FetchError {
	return newFetchError(StepReferrers, KindReferrersUnavailable, err)
}

// newBlobError builds a FetchError for a failed referrer image / blob fetch.
func newBlobError(err error) *FetchError {
	return newFetchError(StepBlob, KindBlobError, err)
}

// classifyTransport maps an error to a stable FailureKind and, when the error
// is an OCI transport error, the HTTP status code.
func classifyTransport(err error) (FailureKind, int) {
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout, 0
	}
	if errors.Is(err, context.Canceled) {
		return KindCanceled, 0
	}

	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		switch transportErr.StatusCode {
		case http.StatusUnauthorized:
			return KindUnauthorized, transportErr.StatusCode
		case http.StatusForbidden:
			return KindForbidden, transportErr.StatusCode
		case http.StatusNotFound:
			return KindNotFound, transportErr.StatusCode
		case http.StatusTooManyRequests:
			return KindThrottled, transportErr.StatusCode
		}
		for _, diagnostic := range transportErr.Errors {
			if diagnostic.Code == transport.UnauthorizedErrorCode {
				return KindUnauthorized, transportErr.StatusCode
			}
			if diagnostic.Code == transport.DeniedErrorCode {
				return KindForbidden, transportErr.StatusCode
			}
			if diagnostic.Code == transport.TooManyRequestsErrorCode {
				return KindThrottled, transportErr.StatusCode
			}
		}
		return KindUnknown, transportErr.StatusCode
	}

	return KindUnknown, 0
}

// kindFromContext classifies a context error.
func kindFromContext(err error) FailureKind {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return KindTimeout
	case errors.Is(err, context.Canceled):
		return KindCanceled
	default:
		return KindUnknown
	}
}

// finalizeFetchError normalizes the error returned after all attempts are
// exhausted into a FetchError carrying the total number of attempts.
func finalizeFetchError(err error, attempts int) error {
	if err == nil {
		// Defensive: this is only reached when the retry loop ran zero
		// iterations (maxAttempts < 1), so no attempt was ever made.
		return &FetchError{
			Kind:     KindUnknown,
			Attempts: 0,
			Err:      errors.New("no bundle fetch attempts were made"),
		}
	}
	var fe *FetchError
	if errors.As(err, &fe) {
		fe.Attempts = attempts
		return fe
	}
	kind, code := classifyTransport(err)
	return &FetchError{
		Kind:        kind,
		StatusCode:  code,
		Attempts:    attempts,
		Recoverable: true,
		Err:         err,
	}
}

// Classify extracts a stable, low-cardinality failure reason, the fetch step,
// and the number of attempts from a bundle fetch error. It is safe to call
// with any error; unrecognized errors are reported with reason "unknown".
func Classify(err error) (reason string, step string, attempts int) {
	var fe *FetchError
	if errors.As(err, &fe) {
		reason = string(fe.Kind)
		if reason == "" {
			reason = string(KindUnknown)
		}
		return reason, string(fe.Step), fe.Attempts
	}
	return string(KindUnknown), "", 0
}

// GetRemoteOptions returns the options to provide when accessing remote
// OCI registries.
func GetRemoteOptions(kc authn.Keychain) []remote.Option {
	var opts = []remote.Option{
		remote.WithUserAgent(UserAgentString),
		remote.WithAuthFromKeychain(kc),
		remote.WithTransport(registryTransport),
	}

	return opts
}
