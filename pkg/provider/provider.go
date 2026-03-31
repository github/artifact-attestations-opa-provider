package provider

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

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
	BundleFromName(ref name.Reference, remoteOpts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error)
	GetRemoteOptions(ctx context.Context, kc authn.Keychain) []remote.Option
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

	// Get the keychain to be able to access the OCI registry.
	// If the keychain configured is empty, the default keychain is used
	// which works for public registries.
	if kc, err = p.kc.KeyChain(ctx); err != nil {
		slog.Error("validate: error retrieving key chain",
			"error", err)
		return ErrorResponse(fmt.Sprintf("ERROR: KeyChain: %s", err))
	}
	var ro = p.bf.GetRemoteOptions(ctx, kc)

	// iterate over all image references (keys)
	for _, key := range r.Request.Keys {
		var res []*verify.VerificationResult
		var ref name.Reference

		slog.Info("validate: verify signature",
			"image", key)
		if ref, err = name.ParseReference(key); err != nil {
			slog.Error("validate: error parsing reference",
				"image", key,
				"error", err)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "invalid_reference",
			})
			continue
		}

		start := time.Now()
		bundles, hash, err := p.bf.BundleFromName(ref, ro)
		dur := time.Since(start)
		metrics.AttestationsRetrieved.Add(float64(len(bundles)))
		metrics.AttestationsPullTimer.Observe(dur.Seconds())
		slog.Info("validate: fetched OCI bundles",
			"count", len(bundles),
			"duration", dur.Seconds())

		if err != nil {
			metrics.AttestationsRetrieveFail.Inc()
			slog.Error("validate: error fetching bundles",
				"image", key,
				"error", err)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "error_fetching_bundle",
			})
			continue
		}

		if len(bundles) == 0 {
			metrics.AttestationsMissing.Inc()
			slog.Info("validate: no bundles",
				"image", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "image_unsigned",
			})
			continue
		}

		start = time.Now()
		res, err = p.v.Verify(bundles, hash)
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
			return ErrorResponse(fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err))
		}

		var bundleVerified = len(res) > 0
		if bundleVerified {
			slog.Info("validate: found valid signatures",
				"count", len(res),
				"image", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: res,
			})
		} else {
			slog.Info("validate: no valid signatures",
				"image", key)
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
