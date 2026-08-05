package fetcher

import (
	"context"
	"errors"
	"fmt"
	"io"
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
)

// NonRecoverableError represent a bundle fetching error that can't
// be recovered from.
type NonRecoverableError struct {
	Op  string
	Err error
}

func (n *NonRecoverableError) Error() string {
	return fmt.Sprintf("non recoverable error: %s: %v", n.Op, n.Err)
}

func (n *NonRecoverableError) Unwrap() error {
	return n.Err
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

	for i := 0; i < maxAttempts; i++ {
		if i > 0 && delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, nil, fmt.Errorf("error fetching bundle: %w", ctx.Err())
			case <-t.C:
				// we are ready to proceed with next
				// attempt
			}
		}

		ictx, cancel := context.WithTimeout(ctx, timeout)
		b, h, err := attempt(ictx)
		cancel()
		if err == nil {
			return b, h, nil
		}
		lastErr = err
		var nce *NonRecoverableError
		if errors.As(err, &nce) {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("error retrieving bundle: %w", err)
		}
	}

	if lastErr == nil {
		lastErr = errors.New("error (timeout) retrieving bundle")
	}
	return nil, nil, lastErr
}

// DoBundleFromName fetches a sigstore bundle for a container from
// a registry.
func DoBundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	var opts []remote.Option

	opts = append(opts, ro...)
	opts = append(opts, remote.WithContext(ctx))

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		if isAuthenticationError(err) {
			return nil, nil, &NonRecoverableError{Op: "getting image descriptor", Err: err}
		}
		return nil, nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())
	referrers, err := remote.Referrers(digest, opts...)
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

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), opts...)
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
		layer0.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting referrer image: %w", err)
		}
		b := &bundle.Bundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil,
				&NonRecoverableError{
					"unmarshalling bundle JSON",
					err,
				}
		}
		bundles = append(bundles, b)
	}

	if len(bundles) == 0 {
		return nil, nil, nil
	}

	return bundles, &desc.Digest, nil
}

func isAuthenticationError(err error) bool {
	var transportErr *transport.Error
	if !errors.As(err, &transportErr) {
		return false
	}

	if transportErr.StatusCode == http.StatusUnauthorized || transportErr.StatusCode == http.StatusForbidden {
		return true
	}

	for _, diagnostic := range transportErr.Errors {
		if diagnostic.Code == transport.UnauthorizedErrorCode || diagnostic.Code == transport.DeniedErrorCode {
			return true
		}
	}

	return false
}

// GetRemoteOptions returns the options to provide when accessing remote
// OCI registries.
func GetRemoteOptions(kc authn.Keychain) []remote.Option {
	var opts = []remote.Option{
		remote.WithUserAgent(UserAgentString),
		remote.WithAuthFromKeychain(kc),
	}

	return opts
}
