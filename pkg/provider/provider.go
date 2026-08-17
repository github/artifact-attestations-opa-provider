package provider

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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
	BundleFromName(ctx context.Context, ref name.Reference, remoteOpts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error)
	GetRemoteOptions(kc authn.Keychain) []remote.Option
}

// Provider is the implementation for the OPA Gatekeeper external data
// provider.
type Provider struct {
	v           Verifier
	kc          KeyChainProvider
	bf          BundleFetcher
	concurrency int
}

// Option configures optional Provider behavior.
type Option func(*Provider)

// WithConcurrency sets the maximum number of images that are verified
// concurrently within a single request. A value of 1 (the default) preserves
// the original serial per-image processing. Only the outer, per-image loop is
// parallelized; each image still fetches its own attestation bundles serially.
// Values less than 1 are treated as 1.
func WithConcurrency(n int) Option {
	return func(p *Provider) {
		if n < 1 {
			n = 1
		}
		p.concurrency = n
	}
}

// New initializes a Provider with a verifier and a keychain provider. By
// default images within a request are verified serially; pass WithConcurrency
// to verify multiple images in parallel.
func New(v Verifier, k KeyChainProvider, bf BundleFetcher, opts ...Option) *Provider {
	p := &Provider{
		v:           v,
		kc:          k,
		bf:          bf,
		concurrency: 1,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
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

	// Get the keychain to be able to access the OCI registry.
	// If the keychain configured is empty, the default keychain is used
	// which works for public registries.
	if kc, err = p.kc.KeyChain(ctx); err != nil {
		slog.Error("validate: error retrieving key chain",
			"error", err)
		return ErrorResponse(fmt.Sprintf("ERROR: KeyChain: %s", err))
	}
	var ro = p.bf.GetRemoteOptions(kc)

	var keys = r.Request.Keys
	var items = make([]externaldata.Item, len(keys))
	// A non-empty entry signals a request-level system error (a verification
	// failure) raised while processing the image at the same index.
	var sysErrs = make([]string, len(keys))

	// Determine the effective per-request image concurrency. A value of 1
	// preserves the original serial behavior; higher values verify the
	// request's images in parallel using a bounded worker pool. Only this
	// outer, per-image loop is parallelized -- each image still fetches its
	// own attestation bundles serially, on the shared request context.
	var concurrency = p.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(keys) {
		concurrency = len(keys)
	}

	if concurrency <= 1 {
		// Serial path: verify images one at a time and, as before, abort the
		// whole request on the first verification (system) error.
		for i, key := range keys {
			items[i], sysErrs[i] = p.validateImage(ctx, key, ro)
			if sysErrs[i] != "" {
				return ErrorResponse(sysErrs[i])
			}
		}
	} else {
		var wg sync.WaitGroup
		// Bounded semaphore caps the number of images in flight at once.
		var sem = make(chan struct{}, concurrency)
		for i, key := range keys {
			// Acquire a slot before launching so no more than `concurrency`
			// images are verified at the same time.
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				// Recover panics from the pluggable fetcher/verifier here.
				// The serial path runs in the HTTP request goroutine, where
				// net/http recovers per-request panics; a panic in this child
				// goroutine would instead crash the whole provider process.
				// Convert it into the image's system error so one malformed
				// request or dependency panic cannot take the provider down.
				defer func() {
					if r := recover(); r != nil {
						slog.Error("validate: recovered panic while verifying image",
							"image", key,
							"panic", r,
							"stack", string(debug.Stack()))
						sysErrs[i] = fmt.Sprintf("ERROR: panic verifying %q: %v", key, r)
					}
				}()
				items[i], sysErrs[i] = p.validateImage(ctx, key, ro)
			})
		}
		wg.Wait()
	}

	// Assemble the response in the original key order. A verification error
	// for any image yields a system error response for the whole request; the
	// first such error in key order wins so the result is deterministic
	// regardless of serial or parallel execution.
	var results = make([]externaldata.Item, 0, len(keys))
	for i := range keys {
		if sysErrs[i] != "" {
			return ErrorResponse(sysErrs[i])
		}
		results = append(results, items[i])
	}

	resp.Response.Items = results
	return &resp
}

// validateImage verifies a single image reference and returns the externaldata
// item to include in the response. A non-empty second return value indicates a
// request-level system error (a verification failure) that must abort the
// entire request; in that case the returned item is empty.
func (p *Provider) validateImage(ctx context.Context, key string, ro []remote.Option) (externaldata.Item, string) {
	slog.Info("validate: verify signature",
		"image", key)

	ref, err := name.ParseReference(key)
	if err != nil {
		slog.Error("validate: error parsing reference",
			"image", key,
			"error", err)
		return externaldata.Item{
			Key:   key,
			Error: "invalid_reference",
		}, ""
	}

	start := time.Now()
	bundles, hash, err := p.bf.BundleFromName(ctx, ref, ro)
	dur := time.Since(start)
	// Record the fetch latency for both successful and failed fetches.
	// The tail of this histogram (failed fetches timing out) is a key
	// signal when troubleshooting registry latency, so it must include
	// failures.
	metrics.AttestationsPullTimer.Observe(dur.Seconds())

	if err != nil {
		reason, step, attempts := fetcher.Classify(err)
		metrics.AttestationsRetrieveFail.WithLabelValues(reason).Inc()
		slog.Error("validate: error fetching bundles",
			"image", key,
			"reason", reason,
			"step", step,
			"attempts", attempts,
			"duration_s", dur.Seconds(),
			"error", err)
		return externaldata.Item{
			Key:   key,
			Error: "error_fetching_bundle_" + reason,
		}, ""
	}

	metrics.AttestationsRetrieved.Add(float64(len(bundles)))
	slog.Info("validate: fetched OCI bundles",
		"image", key,
		"count", len(bundles),
		"duration_s", dur.Seconds())

	if len(bundles) == 0 {
		metrics.AttestationsMissing.Inc()
		slog.Info("validate: no bundles",
			"image", key)
		return externaldata.Item{
			Key:   key,
			Error: "image_unsigned",
		}, ""
	}

	start = time.Now()
	res, err := p.v.Verify(bundles, hash)
	dur = time.Since(start)
	metrics.AttestationsVerTimer.Observe(dur.Seconds())
	metrics.AttestationsVerOk.Add(float64(len(res)))
	var fail = len(bundles) - len(res)
	if fail > 0 {
		metrics.AttestationsVerFail.Add(float64(fail))
	}

	if err != nil {
		slog.Error("validate: verification error",
			"image", key,
			"image_digest", hash.Hex,
			"error", err)
		return externaldata.Item{}, fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err)
	}

	if len(res) > 0 {
		slog.Info("validate: found valid signatures",
			"count", len(res),
			"image", key)
		return externaldata.Item{
			Key:   key,
			Value: res,
		}, ""
	}

	slog.Info("validate: no valid signatures",
		"image", key)
	return externaldata.Item{
		Key:   key,
		Error: "invalid_signature",
	}, ""
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
