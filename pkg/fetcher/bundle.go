package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

var (
	UserAgentString = fmt.Sprintf("artifact-attestations-opa-provider/%s (%s; %s)",
		"dev",
		runtime.GOOS,
		runtime.GOARCH)
)

// TODO: isn't there an update to remote that remedies the need for this
// workaround?
type noncompliantRegistryTransport struct{}

// RoundTrip will check if a request and associated response fulfill the following:
// 1. The response returns a 406 status code
// 2. The request path contains /referrers/
// If both conditions are met, the response's status code will be overwritten to 404
// This is a temporary solution to handle non compliant registries that return
// an unexpected status code 406 when the go-containerregistry library used
// by this code attempts to make a request to the referrers API.
// The go-containerregistry library can handle 404 response but not a 406 response.
// See the related go-containerregistry issue: https://github.com/google/go-containerregistry/issues/1962
func (a *noncompliantRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if resp.StatusCode == http.StatusNotAcceptable && strings.Contains(req.URL.Path, "/referrers/") {
		resp.StatusCode = http.StatusNotFound
	}

	return resp, err
}

// This is copied from
// https://github.com/github/policy-controller/blob/09dab43394666d59c15ded66aee622097af58b77/pkg/webhook/bundle.go#L125
func BundleFromName(ref name.Reference, remoteOpts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())

	transportOpts := []remote.Option{remote.WithTransport(&noncompliantRegistryTransport{})}
	transportOpts = append(transportOpts, remoteOpts...)
	referrers, err := remote.Referrers(digest, transportOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers: %w", err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers manifest: %w", err)
	}

	bundles := make([]*bundle.Bundle, 0)

	for _, refDesc := range refManifest.Manifests {
		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), remoteOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		layer0, err := layers[0].Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		bundleBytes, err := io.ReadAll(layer0)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling bundle: %w", err)
		}
		bundles = append(bundles, b)
	}
	if len(bundles) == 0 {
		return nil, nil, fmt.Errorf("no bundle found in referrers")
	}
	return bundles, &desc.Digest, nil
}

func GetRemoteOptions(ctx context.Context, kc authn.Keychain) []remote.Option {
	var opts = []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(UserAgentString),
		remote.WithAuthFromKeychain(kc),
	}

	return opts
}
