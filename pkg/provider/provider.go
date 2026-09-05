package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptrace"
	"strconv"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
)

// Verifier verifies a set of bundles related to an image's digest.
type Verifier interface {
	Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error)
}

// KeyChainProvider returns a keychain to use to authorize access to remote
// OCI registries.
type KeyChainProvider interface {
	KeyChain(ctx context.Context) (authn.Keychain, error)
}

// BundleFetcher fetches bundles from a remote OCI registry.
type BundleFetcher interface {
	BundleFromName(ctx context.Context, ref name.Reference, remoteOpts []remote.Option) (fetcher.BundleResult, error)
	GetRemoteOptions(kc authn.Keychain) []remote.Option
}

// Provider is the implementation for the OPA Gatekeeper external data
// provider.
type Provider struct {
	v  Verifier
	kc KeyChainProvider
	bf BundleFetcher
}

// New initializes a Provider with a verifier and a keychain provider.
func New(v Verifier, k KeyChainProvider, bf BundleFetcher) *Provider {
	return &Provider{
		v:  v,
		kc: k,
		bf: bf,
	}
}

// Validate implements the OPA Gatekeeper external data provider per
// https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata#implementation
// The request contains a list of image references (keys).
// For each image ref, request any stored bundles, validate them
// and populate the complete verification result for the response to OPA
// Gatekeeper to allow for any rego policy to be applied.
// This means that during verification, no identity is verified, only that
// cryptographic properties holds up given the configured trust roots.
func (p *Provider) Validate(ctx context.Context, r *externaldata.ProviderRequest) *externaldata.ProviderResponse {
	var results = []externaldata.Item{}
	var resp = externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}
	var kc authn.Keychain
	var rstart = time.Now()
	var err error

	// Record the number of images (keys) in this request. Gatekeeper sends
	// every image in a pod as a single request, so this captures the pod's
	// image count. request_id/image_count/image_index are threaded through the
	// per-image logs below so a single failure line (e.g. a fetch timeout) can
	// be traced back to whether it was a solo or a large multi-image request.
	var imageCount = len(r.Request.Keys)

	// systemErr marks a request the provider could not complete: a bundle
	// fetch failed, or - were either branch reachable - the keychain could not
	// be built or verification itself errored. It drives the request timer's
	// outcome, which reports whether the provider processed the request -
	// deliberately not whether the images turned out to be properly attested.
	// An unsigned or unverifiable image is a processed request: the provider
	// did its job and the answer was "no". Declared before the deferred observe
	// so the closure captures it, and read only at return.
	systemErr := false
	defer func() {
		outcome := "success"
		if systemErr {
			outcome = "failure"
		}
		metrics.AttestationsReqTimer.
			WithLabelValues(imageCountLabel(imageCount), outcome).
			Observe(time.Since(rstart).Seconds())
	}()

	var requestID = uuid.NewString()
	var reqLog = slog.With(
		"request_id", requestID,
		"image_count", imageCount)
	reqLog.Info("validate: received request")

	// Get the keychain to be able to access the OCI registry.
	// If the keychain configured is empty, the default keychain is used
	// which works for public registries.
	// Unreachable today: KeyChainProvider.KeyChain always returns a nil error.
	// Retained because the interface permits one.
	if kc, err = p.kc.KeyChain(ctx); err != nil {
		systemErr = true
		reqLog.Error("validate: error retrieving key chain",
			"error", err)
		return ErrorResponse(fmt.Sprintf("ERROR: KeyChain: %s", err))
	}
	var ro = p.bf.GetRemoteOptions(kc)

	// iterate over all image references (keys)
	for i, key := range r.Request.Keys {
		var res []*verify.VerificationResult
		var ref name.Reference

		var imgLog = reqLog.With(
			"image", key,
			"image_index", i+1)

		imgLog.Info("validate: verify signature")
		if ref, err = name.ParseReference(key); err != nil {
			imgLog.Error("validate: error parsing reference",
				"error", err)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "invalid_reference",
			})
			continue
		}

		start := time.Now()
		// Attach a connection trace so that, if the fetch fails, the failure
		// line can report which connection phase (DNS, connect, TLS, reuse, or
		// time-to-first-byte) the request stalled in. The trace rides on the
		// context, so it propagates to every registry call across retries.
		fctx := ctx
		var tc *fetcher.TraceCollector
		if fetcher.TraceEnabled {
			tc = fetcher.NewTraceCollector()
			fctx = httptrace.WithClientTrace(ctx, tc.Trace())
		}
		result, err := p.bf.BundleFromName(fctx, ref, ro)
		dur := time.Since(start)
		// Label the per-image fetch duration by outcome so success-latency
		// percentiles and failure durations can be read apart; on failure the
		// reason/step/attempts dimensions carry the failure taxonomy. The
		// failure tail (fetches timing out) is a key registry-latency signal,
		// so it is observed here alongside successes.
		outcome, reason, step, attempts := "success", "none", "none", 0
		if err != nil {
			outcome = "failure"
			reason, step, attempts = fetcher.Classify(err)
		} else {
			attempts = result.Attempts
		}
		metrics.AttestationsPullTimer.
			WithLabelValues(outcome, reason, step, strconv.Itoa(attempts)).
			Observe(dur.Seconds())

		if err != nil {
			status := strconv.Itoa(fetcher.FailureStatus(err))
			metrics.AttestationsRetrieveFail.WithLabelValues(reason, step, status).Inc()
			// The connection-phase fields ride on the existing failure line, so
			// there is no added log volume on the success path.
			fields := []any{
				"reason", reason,
				"step", step,
				"attempts", attempts,
				"attempt_trail", fetcher.AttemptTrail(err),
				"duration_s", dur.Seconds(),
				"error", err,
			}
			if tc != nil {
				fields = append(fields, tc.Fields()...)
			}
			imgLog.Error("validate: error fetching bundles", fields...)

			// A bundle whose layer we read to completion and whose digest was
			// verified, but which then failed a purely local JSON decode, is a
			// deterministic snapshot of the artifact: no I/O remains that could
			// make it flap. Report it per-image so the caller caches the denial
			// instead of forcing a full fetch-and-decode on every retry.
			//
			// Deliberately narrower than "was addressed by digest": blob_error
			// is also digest-addressed but mixes transport faults with content
			// faults, so it must not be cached.
			var fe *fetcher.FetchError
			if errors.As(err, &fe) && fe.Kind == fetcher.KindBundleInvalid {
				results = append(results, externaldata.Item{
					Key:   key,
					Error: "error_fetching_bundle_" + reason,
				})
				continue
			}

			// Every other fetch failure says nothing durable about the image,
			// so it must not be reported as a per-image result: callers cache
			// per-image outcomes and replay them, turning a momentary blip into
			// a sustained failure. Abort the whole request instead.
			//
			// This includes 404s. They look like a verdict, but tag resolution
			// is mutable and replicated, and in practice they are dominated by
			// replication lag that clears in seconds.
			systemErr = true
			reqLog.Error("validate: aborting request",
				"reason", reason,
				"step", step,
				"image_index", i+1,
				"images_processed", len(results),
				"images_skipped", imageCount-(i+1))
			// Stop here rather than fetching the remaining images: they share
			// one already-depleted request budget, so they would most likely
			// fail the same way and delay the response.
			//
			// Items completed earlier in this request are still returned. The
			// caller caches per-image results, so returning them means a retry
			// re-fetches only what is genuinely missing; the failing image is
			// omitted precisely so it is NOT cached. Callers are expected to
			// disregard items while a system error is set, so returning them
			// cannot be acted on - it only avoids discarding completed work.
			resp.Response.Items = results
			resp.Response.SystemError = fmt.Sprintf(
				"ERROR: BundleFromName(%q): reason=%s step=%s", key, reason, step)
			return &resp
		}

		metrics.AttestationsRetrieved.Add(float64(len(result.Bundles)))
		fetchedFields := []any{
			"count", len(result.Bundles),
			"duration_s", dur.Seconds(),
			"attempts", result.Attempts,
		}
		// A retry-rescued fetch (more than one attempt) succeeded only after
		// earlier attempts failed; surface those prior outcomes so a success
		// that masked real fetch failures is still visible. A first-attempt
		// success adds nothing, so the field stays off the common path.
		if result.Attempts > 1 {
			fetchedFields = append(fetchedFields, "attempt_trail", result.AttemptTrail())
		}
		imgLog.Info("validate: fetched OCI bundles", fetchedFields...)

		if len(result.Bundles) == 0 {
			metrics.AttestationsMissing.Inc()
			imgLog.Info("validate: no bundles")
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "image_unsigned",
			})
			continue
		}

		start = time.Now()
		res, err = p.v.Verify(result.Bundles, result.Hash)
		dur = time.Since(start)
		metrics.AttestationsVerTimer.Observe(dur.Seconds())
		metrics.AttestationsVerOk.Add(float64(len(res)))
		var fail = len(result.Bundles) - len(res)
		if fail > 0 {
			metrics.AttestationsVerFail.Add(float64(fail))
		}

		// Unreachable today: both production Verifier implementations always
		// return a nil error. Retained because the interface permits one.
		if err != nil {
			systemErr = true
			imgLog.Error("validate: verification error",
				"image_digest", result.Hash.Hex,
				"error", err)
			return ErrorResponse(fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err))
		}

		var bundleVerified = len(res) > 0
		if bundleVerified {
			imgLog.Info("validate: found valid signatures",
				"count", len(res))
			results = append(results, externaldata.Item{
				Key:   key,
				Value: res,
			})
		} else {
			imgLog.Info("validate: no valid signatures")
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "invalid_signature",
			})
		}
	}

	resp.Response.Items = results
	return &resp
}

// ErrorResponse prepare a proper error response per the documentation
// https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata#implementation
func ErrorResponse(s string) *externaldata.ProviderResponse {
	var resp = externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}
	resp.Response.SystemError = s

	return &resp
}

// maxImageCountLabel bounds the request timer's images label. The per-request
// image count is a handful in practice, but the handler accepts an arbitrary
// number of keys from the request body, so exact counts are kept only up to
// this cap and anything larger folds into a single overflow bucket. This keeps
// the histogram's cardinality finite regardless of request input.
const maxImageCountLabel = 10

// imageCountLabel renders a request's image count as a bounded label value: the
// exact count up to maxImageCountLabel, or "<max>+" for anything beyond it.
func imageCountLabel(n int) string {
	if n > maxImageCountLabel {
		return strconv.Itoa(maxImageCountLabel) + "+"
	}
	return strconv.Itoa(n)
}
