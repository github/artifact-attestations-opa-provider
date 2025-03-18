package provider

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
)

type Verifier interface {
	Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error)
}

type Provider struct {
	v Verifier
}

func New(v Verifier) *Provider {
	return &Provider{
		v: v,
	}
}

func (p *Provider) Validate(r *externaldata.ProviderRequest) *externaldata.ProviderResponse {
	var resp = externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	results := make([]externaldata.Item, 0)

	// iterate over all keys
	for _, key := range r.Request.Keys {
		var res []*verify.VerificationResult
		var ref name.Reference
		var remoteOpts = []remote.Option{}
		var err error

		fmt.Println("provier::validate verify signature for:", key)
		if ref, err = name.ParseReference(key); err != nil {
			fmt.Printf("provier::validate error parsing reference: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: ParseReference(%q): %v", key, err))
		}

		b, h, err := fetcher.BundleFromName(ref, remoteOpts)
		if err != nil {
			fmt.Printf("provier::validate error fetching bundles: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: FromBundle(%q): %v", key, err))
		}

		if res, err = p.v.Verify(b, h); err != nil {
			fmt.Printf("provier::validate error calling verify: %s\n", err)
			return ErrorResponse(fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err))
		}

		var bundleVerified = len(res) > 0
		if bundleVerified {
			fmt.Printf("provier::validate %d valid signatures found for %s\n",
				len(res),
				key)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: res,
			})
		} else {
			fmt.Printf("provier::validate no valid signatures found for: %s\n", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: key + "_unsigned",
			})
		}
	}

	resp.Response.Items = results
	return &resp
}

func ErrorResponse(s string) *externaldata.ProviderResponse {
	var resp = externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}
	resp.Response.SystemError = s

	return &resp
}
