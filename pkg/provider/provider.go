package provider

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
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

// Provider is the implementation for the OPA Gatekeeper external data
// provider.
type Provider struct {
	v  Verifier
	kc KeyChainProvider
}

// New initializes a Provider with a verifier and a keychain provider.
func New(v Verifier, k KeyChainProvider) *Provider {
	return &Provider{
		v:  v,
		kc: k,
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
	var err error

	// Get the keychain to be able to access the OCI registry.
	// If the keychain configured is empty, the default keychain is used
	// which works for public registries.
	if kc, err = p.kc.KeyChain(ctx); err != nil {
		fmt.Printf("provider::validate error retrieving key chain: %s\n", err)
		return ErrorResponse(fmt.Sprintf("ERROR: KeyChain: %s", err))
	}
	var ro = fetcher.GetRemoteOptions(ctx, kc)

	// iterate over all image references (keys)
	for _, key := range r.Request.Keys {
		var res []*verify.VerificationResult
		var ref name.Reference

		fmt.Println("provider::validate verify signature for:", key)
		if ref, err = name.ParseReference(key); err != nil {
			fmt.Printf("provider::validate error parsing reference: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: ParseReference(%q): %v", key, err))
		}

		b, h, err := fetcher.BundleFromName(ref, ro)
		if err != nil {
			fmt.Printf("provider::validate error fetching bundles: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: FromBundle(%q): %v", key, err))
		}

		if res, err = p.v.Verify(b, h); err != nil {
			fmt.Printf("provider::validate error calling verify: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err))
		}

		var bundleVerified = len(res) > 0
		if bundleVerified {
			fmt.Printf("provider::validate %d valid signatures found for %s\n",
				len(res),
				key)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: res,
			})
		} else {
			fmt.Printf("provider::validate no valid signatures found for: %s\n", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: key + "_unsigned",
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
