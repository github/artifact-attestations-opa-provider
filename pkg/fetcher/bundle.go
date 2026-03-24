package fetcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

var (
	// UserAgentString to use when accessing remote OCI registries.
	UserAgentString = fmt.Sprintf("artifact-attestations-opa-provider/%s (%s; %s)",
		"dev",
		runtime.GOOS,
		runtime.GOARCH)
)

// MaxBundleSize is the max number of bytes read from a remote OCI registry
// when fetching a bundle. The Default value is 10MB.
var MaxBundleSize int64 = 10 << 20

// DefaultBundleFetcher is the default implementation of the BundleFetcher.
type DefaultBundleFetcher struct{}

// BundleFromName fetches a sigstore bundle for a container from the OCI
// registry.
func (*DefaultBundleFetcher) BundleFromName(ref name.Reference, remoteOpts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	return BundleFromName(ref, remoteOpts)
}

// GetRemoteOptions returns the options to provide when accessing remote.
func (*DefaultBundleFetcher) GetRemoteOptions(ctx context.Context, kc authn.Keychain) []remote.Option {
	return GetRemoteOptions(ctx, kc)
}

// BundleFromName fetches a sigstore bundle for a container from
// a registry.
// This is based on
// https://github.com/github/policy-controller/blob/09dab43394666d59c15ded66aee622097af58b77/pkg/webhook/bundle.go#L125
func BundleFromName(ref name.Reference, remoteOpts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())
	referrers, err := remote.Referrers(digest, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers: %w", err)
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting referrers manifest: %w", err)
	}

	bundles := make([]*bundle.Bundle, 0)

	for _, refDesc := range refManifest.Manifests {
		var refImg v1.Image
		var layers []v1.Layer
		var layer0 io.ReadCloser
		var err error

		if !strings.HasPrefix(refDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err = remote.Image(ref.Context().Digest(refDesc.Digest.String()), remoteOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		layers, err = refImg.Layers()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image layers: %w", err)
		}
		if len(layers) == 0 {
			return nil, nil, errors.New("error getting referrer image: no layers found")
		}
		layer0, err = layers[0].Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("error decompressing layer: %w", err)
		}
		bundleBytes, err := io.ReadAll(io.LimitReader(layer0,
			MaxBundleSize+1))
		layer0.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("error reading bundle layer: %w", err)
		}

		// check if we didn't read all the data
		if int64(len(bundleBytes)) > MaxBundleSize {
			return nil, nil, fmt.Errorf("bundle size exceeds maximum allowed size of %d bytes", MaxBundleSize)
		}

		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling bundle: %w", err)
		}
		bundles = append(bundles, b)
	}

	if len(bundles) == 0 {
		return nil, nil, nil
	}

	return bundles, &desc.Digest, nil
}

// GetRemoteOptions returns the options to provide when accessing remote
// OCI registries.
func GetRemoteOptions(ctx context.Context, kc authn.Keychain) []remote.Option {
	var opts = []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(UserAgentString),
		remote.WithAuthFromKeychain(kc),
	}

	return opts
}
