package provider

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
)

type Verifier interface {
	Verify(bundles []*bundle.Bundle, h *v1.Hash, signer, issuer string) ([]*verify.VerificationResult, error)
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

		fmt.Println("verify signature for:", key)
		if ref, err = name.ParseReference(key); err != nil{
			return ErrorResponse(fmt.Sprintf("ERROR: ParseReference(%q): %v", key, err))
		}
		fmt.Printf("ref: %+v\n", ref)

		b, h, err := fetcher.BundleFromName(ref, remoteOpts)
		if err != nil {
			return ErrorResponse(fmt.Sprintf("ERROR: FromBundle(%q): %v", key, err))
		}

		var issuer = ""
		var signer = ""
		if res, err = p.v.Verify(b, h, issuer, signer); err != nil {
			return ErrorResponse(fmt.Sprintf("ERROR: VerifyImageSignatures(%q): %v", key, err))
		}

		fmt.Println(res)

		// var checkedSignatures []oci.Signature
		var checkedSignatures = []struct{}{}
		var bundleVerified = false

		if bundleVerified {
			fmt.Println("signature verified for:", key)
			fmt.Printf("%d number of valid signatures found for %s, found signatures: %v\n", len(checkedSignatures), key, checkedSignatures)
			results = append(results, externaldata.Item{
				Key:   key,
				Value: key + "_valid",
			})
		} else {
			fmt.Printf("no valid signatures found for: %s\n", key)
			results = append(results, externaldata.Item{
				Key:   key,
				Error: key + "_invalid",
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
