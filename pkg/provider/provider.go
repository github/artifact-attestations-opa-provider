package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/httptrace"
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

	defer func() {
		var dur = time.Since(rstart)
		metrics.AttestationsReqTimer.Observe(dur.Seconds())
	}()

	// Record the number of images (keys) in this request. Gatekeeper sends
	// every image in a pod as a single request, so this captures the pod's
	// image count. request_id/image_count/image_index are threaded through the
	// per-image logs below so a single failure line (e.g. a fetch timeout) can
	// be traced back to whether it was a solo or a large multi-image request.
	var imageCount = len(r.Request.Keys)
	var requestID = uuid.NewString()
	var reqLog = slog.With(
		"request_id", requestID,
		"image_count", imageCount)
	metrics.AttestationsReqImages.Observe(float64(imageCount))
	reqLog.Info("validate: received request")

	// Get the keychain to be able to access the OCI registry.
	// If the keychain configured is empty, the default keychain is used
	// which works for public registries.
	if kc, err = p.kc.KeyChain(ctx); err != nil {
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
		// Record the fetch latency for both successful and failed fetches.
		// The tail of this histogram (failed fetches timing out) is a key
		// signal when troubleshooting registry latency, so it must include
		// failures.
		metrics.AttestationsPullTimer.Observe(dur.Seconds())

		if err != nil {
			reason, step, errAttempts := fetcher.Classify(err)
			metrics.AttestationsRetrieveFail.WithLabelValues(reason).Inc()
			// The connection-phase fields ride on the existing failure line, so
			// there is no added log volume on the success path.
			fields := []any{
				"reason", reason,
				"step", step,
				"attempts", errAttempts,
				"attempt_trail", fetcher.AttemptTrail(err),
				"duration_s", dur.Seconds(),
				"error", err,
			}
			if tc != nil {
				fields = append(fields, tc.Fields()...)
			}
			imgLog.Error("validate: error fetching bundles", fields...)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "error_fetching_bundle_" + reason,
			})
			continue
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

		if err != nil {
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
