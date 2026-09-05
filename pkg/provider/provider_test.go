package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/github/artifact-attestations-opa-provider/pkg/metrics"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	validImageName  = "ghcr.io/github/artifact-attestations-opa-provider:latest"
	brokenImageName = "ghcr.io/github/artifact-attestations-opa-provider:broken"
)

var okBundle = `
{
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "verificationMaterial": {
    "timestampVerificationData": {
      "rfc3161Timestamps": [
        {
          "signedTimestamp": "MIIC0DADAgEAMIICxwYJKoZIhvcNAQcCoIICuDCCArQCAQMxDTALBglghkgBZQMEAgIwgbsGCyqGSIb3DQEJEAEEoIGrBIGoMIGlAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgV/XDPdN5CS6qIC2UrnOPrpwGy8p6bwMJPcmil9ocRPUCFCoCc8gLtnOulUiL614tJf+Y/O5cGA8yMDI1MDUwNzA4MDUxMFowAwIBAaA2pDQwMjEVMBMGA1UEChMMR2l0SHViLCBJbmMuMRkwFwYDVQQDExBUU0EgVGltZXN0YW1waW5noAAxggHeMIIB2gIBATBKMDIxFTATBgNVBAoTDEdpdEh1YiwgSW5jLjEZMBcGA1UEAxMQVFNBIGludGVybWVkaWF0ZQIUH7swiMTn+svhcDh80OeZccDTj7AwCwYJYIZIAWUDBAICoIIBBTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI1MDUwNzA4MDUxMFowPwYJKoZIhvcNAQkEMTIEMAfJD2LkANL5fJKSBtR2qxDvSaDIhJ3ClT+fIx0iUhA4K4x+nJGt2ybC0GQnXyjDrDCBhwYLKoZIhvcNAQkQAi8xeDB2MHQwcgQge4hKwpLKIm2WEaNP5HJL61hDuLAIywwJMabPY0rcPsMwTjA2pDQwMjEVMBMGA1UEChMMR2l0SHViLCBJbmMuMRkwFwYDVQQDExBUU0EgaW50ZXJtZWRpYXRlAhQfuzCIxOf6y+FwOHzQ55lxwNOPsDAKBggqhkjOPQQDAwRnMGUCMF7XHsqCkzENej1yYK0qEBT+lZhtDrI8ramw2udLF3oL4f8RcotRTpip2/0aFvaGKwIxAM9OkAbFcVLLphH2fJx8un71iH1ngftMQIOAah4qmIDR/TN4MbEaKUevQA+q8VOy0g=="
        }
      ]
    },
    "certificate": {
      "rawBytes": "MIIG1jCCBlygAwIBAgIUVWNQGdCQpVhBbHSkIcLYDduZ1WowCgYIKoZIzj0EAwMwODEVMBMGA1UEChMMR2l0SHViLCBJbmMuMR8wHQYDVQQDExZGdWxjaW8gSW50ZXJtZWRpYXRlIGwyMB4XDTI1MDUwNzA4MDUxMFoXDTI1MDUwNzA4MTUxMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF1ztgKRPF/HI28a4lDRNJBb4djoUzFDnSoHyszDMuoVXWjLQ7L0KCjyFsSxIZdSK6/4Abu7DTO5kneqfJ46NcajggV6MIIFdjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFCVUdj4tJhY+44hfGIT4TH8rdKVTMB8GA1UdIwQYMBaAFDIm/c+GWAXEADU1b1QmtyqExmwVMHsGA1UdEQEB/wRxMG+GbWh0dHBzOi8vZ2l0aHViLmNvbS9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlci8uZ2l0aHViL3dvcmtmbG93cy9kb2NrZXIueWFtbEByZWZzL3B1bGwvMzEvbWVyZ2UwOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAaBgorBgEEAYO/MAECBAxwdWxsX3JlcXVlc3QwNgYKKwYBBAGDvzABAwQoZjQ5MmU4Y2YwMTQ0NmM0MWYzNzZhYTA3NjU2ZGM0MjY2ZjE1NDczOTApBgorBgEEAYO/MAEEBBtCdWlsZCBhbmQgcHVzaCBEb2NrZXIgaW1hZ2UwNwYKKwYBBAGDvzABBQQpZ2l0aHViL2FydGlmYWN0LWF0dGVzdGF0aW9ucy1vcGEtcHJvdmlkZXIwIAYKKwYBBAGDvzABBgQScmVmcy9wdWxsLzMxL21lcmdlMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTB9BgorBgEEAYO/MAEJBG8MbWh0dHBzOi8vZ2l0aHViLmNvbS9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlci8uZ2l0aHViL3dvcmtmbG93cy9kb2NrZXIueWFtbEByZWZzL3B1bGwvMzEvbWVyZ2UwOAYKKwYBBAGDvzABCgQqDChmNDkyZThjZjAxNDQ2YzQxZjM3NmFhMDc2NTZkYzQyNjZmMTU0NzM5MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBMBgorBgEEAYO/MAEMBD4MPGh0dHBzOi8vZ2l0aHViLmNvbS9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlcjA4BgorBgEEAYO/MAENBCoMKGY0OTJlOGNmMDE0NDZjNDFmMzc2YWEwNzY1NmRjNDI2NmYxNTQ3MzkwIgYKKwYBBAGDvzABDgQUDBJyZWZzL3B1bGwvMzEvbWVyZ2UwGQYKKwYBBAGDvzABDwQLDAk5NDg0NzE3NDIwKQYKKwYBBAGDvzABEAQbDBlodHRwczovL2dpdGh1Yi5jb20vZ2l0aHViMBQGCisGAQQBg78wAREEBgwEOTkxOTB9BgorBgEEAYO/MAESBG8MbWh0dHBzOi8vZ2l0aHViLmNvbS9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlci8uZ2l0aHViL3dvcmtmbG93cy9kb2NrZXIueWFtbEByZWZzL3B1bGwvMzEvbWVyZ2UwOAYKKwYBBAGDvzABEwQqDChjNDU2MmFhOTJiYTFkMDVmYzkxMDE1MmI1YTM5Yzg5NDkwMjA2ODM5MBwGCisGAQQBg78wARQEDgwMcHVsbF9yZXF1ZXN0MHAGCisGAQQBg78wARUEYgxgaHR0cHM6Ly9naXRodWIuY29tL2dpdGh1Yi9hcnRpZmFjdC1hdHRlc3RhdGlvbnMtb3BhLXByb3ZpZGVyL2FjdGlvbnMvcnVucy8xNDg3ODI2NzEyNy9hdHRlbXB0cy8xMBcGCisGAQQBg78wARYECQwHcHJpdmF0ZTAKBggqhkjOPQQDAwNoADBlAjBJvjEH5/OWrT9yCQvolMb2Fo02TjtJTxkGWlC6WKYPklDwjy4Z3K0UtwLlGeNJuXgCMQDNdIWemk3CH/Fw25X9+a5FYu3mbmBH1Ca5lPk+gDuQkDp5E8ugEgR0cpVqRJS3Ys8="
    }
  },
  "dsseEnvelope": {
    "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZ2hjci5pby9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlciIsImRpZ2VzdCI6eyJzaGEyNTYiOiJkNTdmOTIxMjA5N2I4NmM4ZDc1MTU4ZWExZDk3NDcyMWU3YzZmOGMzM2JkNzc4MzhiMjQyYzhmNmEyZDIxODEzIn19XSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvcHJvdmVuYW5jZS92MSIsInByZWRpY2F0ZSI6eyJidWlsZERlZmluaXRpb24iOnsiYnVpbGRUeXBlIjoiaHR0cHM6Ly9hY3Rpb25zLmdpdGh1Yi5pby9idWlsZHR5cGVzL3dvcmtmbG93L3YxIiwiZXh0ZXJuYWxQYXJhbWV0ZXJzIjp7IndvcmtmbG93Ijp7InJlZiI6InJlZnMvcHVsbC8zMS9tZXJnZSIsInJlcG9zaXRvcnkiOiJodHRwczovL2dpdGh1Yi5jb20vZ2l0aHViL2FydGlmYWN0LWF0dGVzdGF0aW9ucy1vcGEtcHJvdmlkZXIiLCJwYXRoIjoiLmdpdGh1Yi93b3JrZmxvd3MvZG9ja2VyLnlhbWwifX0sImludGVybmFsUGFyYW1ldGVycyI6eyJnaXRodWIiOnsiZXZlbnRfbmFtZSI6InB1bGxfcmVxdWVzdCIsInJlcG9zaXRvcnlfaWQiOiI5NDg0NzE3NDIiLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiOTkxOSIsInJ1bm5lcl9lbnZpcm9ubWVudCI6ImdpdGh1Yi1ob3N0ZWQifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL2dpdGh1Yi9hcnRpZmFjdC1hdHRlc3RhdGlvbnMtb3BhLXByb3ZpZGVyQHJlZnMvcHVsbC8zMS9tZXJnZSIsImRpZ2VzdCI6eyJnaXRDb21taXQiOiJmNDkyZThjZjAxNDQ2YzQxZjM3NmFhMDc2NTZkYzQyNjZmMTU0NzM5In19XX0sInJ1bkRldGFpbHMiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9naXRodWIvYXJ0aWZhY3QtYXR0ZXN0YXRpb25zLW9wYS1wcm92aWRlci8uZ2l0aHViL3dvcmtmbG93cy9kb2NrZXIueWFtbEByZWZzL3B1bGwvMzEvbWVyZ2UifSwibWV0YWRhdGEiOnsiaW52b2NhdGlvbklkIjoiaHR0cHM6Ly9naXRodWIuY29tL2dpdGh1Yi9hcnRpZmFjdC1hdHRlc3RhdGlvbnMtb3BhLXByb3ZpZGVyL2FjdGlvbnMvcnVucy8xNDg3ODI2NzEyNy9hdHRlbXB0cy8xIn19fX0=",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "sig": "MEQCIFdFAK3QPqri1L08R7wKIpN3rt06RxnKeM5SO8dZebWCAiBecOxMovN8EfLfaQPmsCG4cA5YkSEaoyx8kNza7m+KZA=="
      }
    ]
  }
}`

var brokenBundle = `{"b0rked"}`

type mockBundle struct {
	bundle string
	hash   string
}

var bundles = map[string]mockBundle{
	validImageName: {
		bundle: okBundle,
		hash:   "d57f9212097b86c8d75158ea1d974721e7c6f8c33bd77838b242c8f6a2d21813",
	},
	brokenImageName: {
		bundle: brokenBundle,
		hash:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	},
}

type mockVerifier struct {
}

func (*mockVerifier) Verify(_ []*bundle.Bundle, _ *v1.Hash) ([]*verify.VerificationResult, error) {
	return nil, nil
}

type mockKeyChainProvider struct {
}

func (*mockKeyChainProvider) KeyChain(_ context.Context) (authn.Keychain, error) {
	return nil, nil
}

type mockBundleFetcher struct {
}

func (*mockBundleFetcher) BundleFromName(_ context.Context, ref name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	if mb, ok := bundles[ref.Name()]; ok {
		var b bundle.Bundle
		err := b.UnmarshalJSON([]byte(mb.bundle))
		if err != nil {
			return fetcher.BundleResult{Attempts: 1}, err
		}
		h := v1.Hash{
			Algorithm: "sha256",
			Hex:       mb.hash,
		}
		return fetcher.BundleResult{
			Bundles:  []*bundle.Bundle{&b},
			Hash:     &h,
			Attempts: 1,
		}, nil
	}

	return fetcher.BundleResult{Attempts: 1}, nil
}

func (*mockBundleFetcher) GetRemoteOptions(_ authn.Keychain) []remote.Option {
	return nil
}

func TestNewProvider(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}

	provider := New(v, kc, bf)

	assert.NotNil(t, provider)
	assert.Equal(t, v, provider.v)
	assert.Equal(t, kc, provider.kc)
	assert.Equal(t, bf, provider.bf)
}

func TestNilValidate(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	assert.NotNil(t, provider)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{"image1", "image2"},
		},
	}
	response := provider.Validate(context.Background(), request)
	assert.NotNil(t, response)
	assert.Equal(t, apiVersion, response.APIVersion)
	assert.Equal(t, externaldata.ProviderKind("ProviderResponse"), response.Kind)
	for _, i := range response.Response.Items {
		assert.Nil(t, i.Value)
		assert.True(t, strings.HasSuffix(i.Error, "_unsigned"))
	}
	assert.Empty(t, response.Response.SystemError)
}

func TestVerifyOk(t *testing.T) {
	v, err := verifier.GHVerifier("")
	require.NoError(t, err)
	assert.NotNil(t, v)
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}

	response := provider.Validate(context.Background(), request)
	assert.NotNil(t, response)
	assert.Equal(t, apiVersion, response.APIVersion)
	assert.Equal(t, externaldata.ProviderKind("ProviderResponse"), response.Kind)
	assert.Len(t, response.Response.Items, 1)
	assert.Equal(t, validImageName, response.Response.Items[0].Key)
	assert.NotNil(t, response.Response.Items[0].Value)
	assert.Empty(t, response.Response.SystemError)
	assert.Empty(t, response.Response.Items[0].Error)
}

func TestVerifyWrongDomain(t *testing.T) {
	v, err := verifier.PGIVerifier()
	require.NoError(t, err)
	assert.NotNil(t, v)
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}

	response := provider.Validate(context.Background(), request)
	assert.NotNil(t, response)
	assert.Equal(t, apiVersion, response.APIVersion)
	assert.Equal(t, externaldata.ProviderKind("ProviderResponse"), response.Kind)
	assert.Len(t, response.Response.Items, 1)
	assert.Nil(t, response.Response.Items[0].Value)
	assert.Equal(t, validImageName, response.Response.Items[0].Key)
	assert.Equal(t, "invalid_signature", response.Response.Items[0].Error)
	assert.Empty(t, response.Response.SystemError)
}

func TestInvalid(t *testing.T) {
	v, err := verifier.GHVerifier("")
	require.NoError(t, err)
	assert.NotNil(t, v)
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	tests := []struct {
		image string
		error string
	}{
		{
			image: "foo+bar",
			error: "invalid_reference",
		},
	}

	for _, tc := range tests {
		request := &externaldata.ProviderRequest{
			APIVersion: apiVersion,
			Kind:       "ProviderRequest",
			Request: externaldata.Request{
				Keys: []string{tc.image},
			},
		}

		response := provider.Validate(context.Background(), request)
		assert.NotNil(t, response)
		assert.Equal(t, apiVersion, response.APIVersion)
		assert.Equal(t, externaldata.ProviderKind("ProviderResponse"), response.Kind)
		assert.Len(t, response.Response.Items, 1)
		assert.Equal(t, tc.error, response.Response.Items[0].Error)
	}
}

// TestInvalidBundleAbortsRequest covers the case lifted out of TestInvalid's
// table. mockBundleFetcher fails brokenImageName with a raw json error, which
// classifies as "unknown" rather than bundle_invalid, so it is a fetch failure
// that aborts the request instead of becoming a cached item error. This test
// never covered the bundle_invalid path; that is pinned by
// TestValidateKeepsBundleInvalidAsItemError.
func TestInvalidBundleAbortsRequest(t *testing.T) {
	v, err := verifier.GHVerifier("")
	require.NoError(t, err)
	provider := New(v, &mockKeyChainProvider{}, &mockBundleFetcher{})

	response := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{brokenImageName},
		},
	})

	require.NotNil(t, response)
	assert.NotEmpty(t, response.Response.SystemError,
		"an unclassified fetch failure must abort the request")
	assert.Empty(t, response.Response.Items,
		"no item may be returned, or the caller will cache the failure")
}

// notFoundBundleFetcher always fails with a 404 (MANIFEST_UNKNOWN) fetch
// error, used to exercise the non-recoverable not_found path.
type notFoundBundleFetcher struct {
	mockBundleFetcher
}

func (*notFoundBundleFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	return fetcher.BundleResult{Attempts: 1}, &fetcher.FetchError{
		Step:        fetcher.StepDescriptor,
		Kind:        fetcher.KindNotFound,
		Attempts:    1,
		StatusCode:  http.StatusNotFound,
		Recoverable: false,
		Err:         errors.New("MANIFEST_UNKNOWN"),
	}
}

// canceledBundleFetcher fails with a canceled fetch error that carries no
// registry response (StatusCode 0), exercising the status="0" counter path
// where the registry never answered.
type canceledBundleFetcher struct {
	mockBundleFetcher
}

func (*canceledBundleFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	return fetcher.BundleResult{Attempts: 3}, &fetcher.FetchError{
		Step:        fetcher.StepDescriptor,
		Kind:        fetcher.KindCanceled,
		Attempts:    3,
		Recoverable: false,
		Err:         context.Canceled,
	}
}

// oneResultVerifier reports one successful verification, so an image whose
// fetch succeeds produces a clean item. mockVerifier returns (nil, nil), which
// with mockBundleFetcher's single bundle yields invalid_signature and would
// defeat the retain assertions.
type oneResultVerifier struct{}

func (*oneResultVerifier) Verify(_ []*bundle.Bundle, _ *v1.Hash) ([]*verify.VerificationResult, error) {
	return []*verify.VerificationResult{{
		MediaType: "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
	}}, nil
}

// timeoutBundleFetcher fails with a timeout that carries no registry response.
type timeoutBundleFetcher struct {
	mockBundleFetcher
	calls int
}

func (f *timeoutBundleFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	f.calls++
	return fetcher.BundleResult{Attempts: 3}, &fetcher.FetchError{
		Step:        fetcher.StepReferrers,
		Kind:        fetcher.KindTimeout,
		Attempts:    3,
		Recoverable: true,
		Err:         errors.New("timeout awaiting response headers"),
	}
}

// okThenTimeoutFetcher succeeds on the first image and then fails, exercising
// the retain-verified-items path.
type okThenTimeoutFetcher struct {
	mockBundleFetcher
	calls int
}

func (f *okThenTimeoutFetcher) BundleFromName(ctx context.Context, ref name.Reference, ro []remote.Option) (fetcher.BundleResult, error) {
	f.calls++
	if f.calls == 1 {
		return f.mockBundleFetcher.BundleFromName(ctx, ref, ro)
	}
	return fetcher.BundleResult{Attempts: 3}, &fetcher.FetchError{
		Step:        fetcher.StepReferrers,
		Kind:        fetcher.KindTimeout,
		Attempts:    3,
		Recoverable: true,
		Err:         errors.New("timeout awaiting response headers"),
	}
}

// TestValidateReturnsSystemErrorOnFetchFailure verifies that a fetch failure
// aborts the request with a system error and no items, so the caller has
// nothing cacheable to replay.
func TestValidateReturnsSystemErrorOnFetchFailure(t *testing.T) {
	provider := New(&mockVerifier{}, &mockKeyChainProvider{}, &timeoutBundleFetcher{})

	resp := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})

	assert.NotEmpty(t, resp.Response.SystemError,
		"a fetch failure must surface as a system error")
	assert.Empty(t, resp.Response.Items,
		"no items may be returned, or the caller will cache the failure")
	assert.Contains(t, resp.Response.SystemError, "timeout")
	assert.Contains(t, resp.Response.SystemError, "referrers")
}

// TestValidateAbortsRemainingImages verifies fail-fast: once the request is
// known to return a system error, later images are not fetched at all.
func TestValidateAbortsRemainingImages(t *testing.T) {
	bf := &timeoutBundleFetcher{}
	provider := New(&mockVerifier{}, &mockKeyChainProvider{}, bf)

	provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName, brokenImageName, validImageName},
		},
	})

	assert.Equal(t, 1, bf.calls,
		"the request must abort on the first fetch failure, not fetch the remaining images")
}

// TestValidateRetainsVerifiedItemsOnAbort verifies that images verified before
// the abort are still returned. They are cacheable by the caller, so a retry
// re-fetches only the images that are genuinely missing.
func TestValidateRetainsVerifiedItemsOnAbort(t *testing.T) {
	okThenTimeout := &okThenTimeoutFetcher{}
	provider := New(&oneResultVerifier{}, &mockKeyChainProvider{}, okThenTimeout)

	resp := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName, brokenImageName}},
	})

	assert.NotEmpty(t, resp.Response.SystemError)
	require.Len(t, resp.Response.Items, 1,
		"the image verified before the abort should still be returned")
	assert.Equal(t, validImageName, resp.Response.Items[0].Key)
	assert.Empty(t, resp.Response.Items[0].Error,
		"the retained item is a clean result, not the failure")
}

// TestValidateAbortsOnNotFound pins the decision that a 404 is NOT treated as a
// cacheable per-image verdict. Fleet data shows these are overwhelmingly
// registry replication lag that clears in seconds, so caching the denial would
// outlive its cause. It also pins that the failure counter still increments
// before the abort, which the operational runbook depends on.
func TestValidateAbortsOnNotFound(t *testing.T) {
	failCounter := metrics.AttestationsRetrieveFail.WithLabelValues("not_found", "descriptor", "404")
	before := testutil.ToFloat64(failCounter)

	provider := New(&mockVerifier{}, &mockKeyChainProvider{}, &notFoundBundleFetcher{})

	resp := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})

	assert.NotEmpty(t, resp.Response.SystemError,
		"a 404 must abort, not become a cached item error")
	assert.Empty(t, resp.Response.Items)

	after := testutil.ToFloat64(failCounter)
	assert.InDelta(t, 1.0, after-before, 0.0001,
		"the fetch-failure counter must still increment before the abort")
}

// bundleInvalidFetcher fails with a decode error on a blob that was fetched
// successfully by digest.
type bundleInvalidFetcher struct {
	mockBundleFetcher
}

func (*bundleInvalidFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	// Attempts must be set on the FetchError, not just on the BundleResult:
	// Classify reads it from the error (bundle.go:637-648), so omitting it
	// emits a misleading attempts="0" label.
	return fetcher.BundleResult{Attempts: 1}, &fetcher.FetchError{
		Step:        fetcher.StepDecode,
		Kind:        fetcher.KindBundleInvalid,
		Attempts:    1,
		Recoverable: false,
		Err:         errors.New("invalid character 'x' looking for beginning of value"),
	}
}

// TestValidateKeepsBundleInvalidAsItemError pins the single exception: the
// layer was read to completion and digest-verified, and only the local JSON
// decode failed, so no I/O remains that could make the outcome flap within a
// cache TTL. Caching it is correct, and NOT caching it would force a full
// fetch-and-decode on every controller retry.
//
// This is deliberately narrower than "was addressed by digest" - blob_error is
// also digest-addressed but mixes transport with content faults.
//
// Note this cannot be exercised through mockBundleFetcher's brokenImageName,
// which returns a raw json error that classifies as "unknown".
func TestValidateKeepsBundleInvalidAsItemError(t *testing.T) {
	provider := New(&mockVerifier{}, &mockKeyChainProvider{}, &bundleInvalidFetcher{})

	resp := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})

	assert.Empty(t, resp.Response.SystemError,
		"a completed, digest-verified decode failure is a verdict, not a provider fault")
	require.Len(t, resp.Response.Items, 1)
	assert.Equal(t, "error_fetching_bundle_bundle_invalid", resp.Response.Items[0].Error)
}

// TestValidateLabelsFetchFailureCounter verifies the fetch-failure counter is
// dimensioned by reason, step, and registry status, including the status="0"
// case where the registry never responded (a cancellation).
func TestValidateLabelsFetchFailureCounter(t *testing.T) {
	canceled := metrics.AttestationsRetrieveFail.WithLabelValues("canceled", "descriptor", "0")
	before := testutil.ToFloat64(canceled)

	provider := New(&mockVerifier{}, &mockKeyChainProvider{}, &canceledBundleFetcher{})
	provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})

	after := testutil.ToFloat64(canceled)
	assert.InDelta(t, 1.0, after-before, 0.0001,
		`fail metric should be labeled reason="canceled" step="descriptor" status="0"`)
}

// errKeyChainProvider always fails to build a keychain, exercising the early
// request-error return before any image is processed.
type errKeyChainProvider struct{}

func (*errKeyChainProvider) KeyChain(_ context.Context) (authn.Keychain, error) {
	return nil, errors.New("keychain boom")
}

// TestImageCountLabel verifies the request timer's images label is bounded: the
// exact count up to the cap, and a single overflow bucket beyond it, so an
// unbounded key count cannot grow histogram cardinality without limit.
func TestImageCountLabel(t *testing.T) {
	assert.Equal(t, "0", imageCountLabel(0))
	assert.Equal(t, "1", imageCountLabel(1))
	assert.Equal(t, "10", imageCountLabel(maxImageCountLabel))
	assert.Equal(t, "10+", imageCountLabel(maxImageCountLabel+1))
	assert.Equal(t, "10+", imageCountLabel(1000))
}

// observeCount returns the number of observations recorded on a histogram
// child, read through the concrete metric behind the Observer.
func observeCount(t *testing.T, o prometheus.Observer) uint64 {
	t.Helper()
	m, ok := o.(prometheus.Metric)
	require.True(t, ok, "histogram child should expose the Metric interface")
	dtoMetric := &dto.Metric{}
	require.NoError(t, m.Write(dtoMetric))
	return dtoMetric.GetHistogram().GetSampleCount()
}

// TestValidateRecordsFetchOutcome verifies the per-image fetch timer records one
// observation on the success child on a clean fetch, and one on the matching
// failure child (carrying reason/step/attempts) when the fetch fails.
func TestValidateRecordsFetchOutcome(t *testing.T) {
	fetch := func(bf BundleFetcher) {
		provider := New(&mockVerifier{}, &mockKeyChainProvider{}, bf)
		provider.Validate(context.Background(), &externaldata.ProviderRequest{
			APIVersion: apiVersion,
			Kind:       "ProviderRequest",
			Request:    externaldata.Request{Keys: []string{validImageName}},
		})
	}

	successChild := metrics.AttestationsPullTimer.WithLabelValues("success", "none", "none", "1")
	failChild := metrics.AttestationsPullTimer.WithLabelValues("failure", "not_found", "descriptor", "1")

	beforeOK := observeCount(t, successChild)
	fetch(&mockBundleFetcher{})
	assert.Equal(t, uint64(1), observeCount(t, successChild)-beforeOK,
		"a clean fetch should observe the success child once")

	beforeFail := observeCount(t, failChild)
	fetch(&notFoundBundleFetcher{})
	assert.Equal(t, uint64(1), observeCount(t, failChild)-beforeFail,
		"a failed fetch should observe the matching failure child once")
}

// TestValidateRecordsRequestOutcome verifies the request timer records one
// observation per request, labelled by the raw image count and whether every
// image verified cleanly (outcome). This replaces the removed request-images
// histogram, whose per-request count is now request_timer{images}'s _count.
func TestValidateRecordsRequestOutcome(t *testing.T) {
	okVerifier, err := verifier.GHVerifier("")
	require.NoError(t, err)

	successChild := metrics.AttestationsReqTimer.WithLabelValues("1", "success")
	failChild := metrics.AttestationsReqTimer.WithLabelValues("1", "failure")

	// A request whose single image verifies cleanly is totally successful.
	beforeOK := observeCount(t, successChild)
	provOK := New(okVerifier, &mockKeyChainProvider{}, &mockBundleFetcher{})
	provOK.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})
	assert.Equal(t, uint64(1), observeCount(t, successChild)-beforeOK,
		"an all-clean request should observe the success child once")

	// A request whose image fails to fetch is not totally successful.
	// The label survived a meaning change: the 404 now lands on "failure"
	// because it returns a system error rather than a per-image item error.
	beforeFail := observeCount(t, failChild)
	provFail := New(&mockVerifier{}, &mockKeyChainProvider{}, &notFoundBundleFetcher{})
	provFail.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{validImageName}},
	})
	assert.Equal(t, uint64(1), observeCount(t, failChild)-beforeFail,
		"a request with a failed image should observe the failure child once")
}

// TestValidateCountsKeychainErrorRequest verifies the request timer still counts
// the request (as a failure) when the keychain build fails before any image is
// processed, so _count covers the early-return path.
func TestValidateCountsKeychainErrorRequest(t *testing.T) {
	child := metrics.AttestationsReqTimer.WithLabelValues("2", "failure")
	before := observeCount(t, child)

	provider := New(&mockVerifier{}, &errKeyChainProvider{}, &mockBundleFetcher{})
	resp := provider.Validate(context.Background(), &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: []string{"image1", "image2"}},
	})
	require.NotEmpty(t, resp.Response.SystemError, "keychain failure should be a system error")

	assert.Equal(t, uint64(1), observeCount(t, child)-before,
		"the keychain-error request should be observed once as a failure")
}

// TestValidateLogsImageContext verifies that per-image log lines carry the
// request-scoped context (request_id, image_count, image_index, attempts) so
// a failed image fetch can be traced back to a solo vs. multi-image request.
func TestValidateLogsImageContext(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &notFoundBundleFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName, brokenImageName},
		},
	}
	provider.Validate(context.Background(), request)

	var entry, fetchErr map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		if m["msg"] == "validate: received request" {
			entry = m
		}
		if m["msg"] == "validate: error fetching bundles" {
			fetchErr = m
		}
	}

	require.NotNil(t, entry, "expected a request entry log line")
	require.NotNil(t, fetchErr, "expected a fetch error log line")

	// JSON numbers decode as float64.
	assert.InDelta(t, 2.0, entry["image_count"], 0.0001)
	assert.NotEmpty(t, entry["request_id"])

	assert.InDelta(t, 2.0, fetchErr["image_count"], 0.0001, "failure line should report the request image count")
	// The first image's fetch fails, which aborts the request before the
	// second image is ever fetched, so there is exactly one failure line and
	// its 1-based image_index must be 1. image_count stays 2: the request
	// really did carry two keys.
	assert.InDelta(t, 1.0, fetchErr["image_index"], 0.0001, "failure line should report the 1-based image position")
	assert.InDelta(t, 1.0, fetchErr["attempts"], 0.0001, "failure line should report the fetch attempt count")
	assert.Equal(t, entry["request_id"], fetchErr["request_id"],
		"per-image failure line should carry the request's correlation id")
}

// traceProbeFetcher records whether a client trace was attached to the fetch
// context and always fails, so the provider's failure-logging path runs and
// its trace fields can be asserted.
type traceProbeFetcher struct {
	mockBundleFetcher
	sawTrace bool
}

func (f *traceProbeFetcher) BundleFromName(ctx context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	f.sawTrace = httptrace.ContextClientTrace(ctx) != nil
	return fetcher.BundleResult{Attempts: 3}, &fetcher.FetchError{
		Step:        fetcher.StepDescriptor,
		Kind:        fetcher.KindTimeout,
		Attempts:    3,
		Recoverable: false,
		Err:         context.DeadlineExceeded,
	}
}

// lastLogLine returns the last JSON log entry in buf whose "msg" equals msg, or
// nil if none is present.
func lastLogLine(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		if m["msg"] == msg {
			found = m
		}
	}
	return found
}

// TestValidateAttachesTraceAndLogsFieldsOnFailure verifies the provider wires a
// client trace onto the fetch context when tracing is enabled and appends the
// connection-phase fields to the failure log line.
func TestValidateAttachesTraceAndLogsFieldsOnFailure(t *testing.T) {
	prevTrace := fetcher.TraceEnabled
	fetcher.TraceEnabled = true
	defer func() { fetcher.TraceEnabled = prevTrace }()

	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &traceProbeFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}
	provider.Validate(context.Background(), request)

	assert.True(t, bf.sawTrace,
		"fetch context should carry an httptrace.ClientTrace when tracing is enabled")

	fetchErr := lastLogLine(t, &buf, "validate: error fetching bundles")
	require.NotNil(t, fetchErr, "expected a fetch error log line")
	// The connection-phase fields ride on the existing failure line.
	assert.Contains(t, fetchErr, "ttfb_ms")
	assert.Contains(t, fetchErr, "conns_new")
	assert.Contains(t, fetchErr, "wrote_request")
	// The pre-existing failure fields must survive alongside the new ones.
	assert.Equal(t, "timeout", fetchErr["reason"])
}

// TestValidateOmitsTraceFieldsWhenDisabled verifies the -registry-trace kill
// switch: with tracing disabled no trace is attached and the failure line
// carries none of the connection-phase fields.
func TestValidateOmitsTraceFieldsWhenDisabled(t *testing.T) {
	prevTrace := fetcher.TraceEnabled
	fetcher.TraceEnabled = false
	defer func() { fetcher.TraceEnabled = prevTrace }()

	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &traceProbeFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}
	provider.Validate(context.Background(), request)

	assert.False(t, bf.sawTrace,
		"fetch context should not carry a trace when tracing is disabled")

	fetchErr := lastLogLine(t, &buf, "validate: error fetching bundles")
	require.NotNil(t, fetchErr, "expected a fetch error log line")
	assert.NotContains(t, fetchErr, "ttfb_ms")
	assert.NotContains(t, fetchErr, "conns_new")
	// The pre-existing failure fields are still present.
	assert.Equal(t, "timeout", fetchErr["reason"])
}

// trailFetcher always fails with a FetchError that carries a per-attempt trail,
// so the provider's failure-logging path can be asserted to surface it.
type trailFetcher struct {
	mockBundleFetcher
}

func (*trailFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	return fetcher.BundleResult{Attempts: 3}, &fetcher.FetchError{
		Step:     fetcher.StepDescriptor,
		Kind:     fetcher.KindCanceled,
		Attempts: 3,
		Trail: []fetcher.AttemptOutcome{
			{Reason: fetcher.KindTimeout, Step: fetcher.StepDescriptor},
			{Reason: fetcher.KindTimeout, Step: fetcher.StepDescriptor},
			{Reason: fetcher.KindCanceled, Step: fetcher.StepDescriptor},
		},
		Recoverable: false,
		Err:         context.Canceled,
	}
}

// TestValidateLogsAttemptTrailOnFailure verifies the provider surfaces the
// per-attempt trail on the fetch failure line, so a terminal cancellation does
// not hide the establishment timeouts that preceded it.
func TestValidateLogsAttemptTrailOnFailure(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &trailFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}
	provider.Validate(context.Background(), request)

	fetchErr := lastLogLine(t, &buf, "validate: error fetching bundles")
	require.NotNil(t, fetchErr, "expected a fetch error log line")
	// The terminal reason stays honest, and the trail rides alongside it.
	assert.Equal(t, "canceled", fetchErr["reason"])
	assert.Equal(t, "timeout:descriptor,timeout:descriptor,canceled:descriptor", fetchErr["attempt_trail"])
}

// rescuedSuccessFetcher returns a successful result that only succeeded after
// earlier attempts failed, carrying their outcomes on the result's trail.
type rescuedSuccessFetcher struct {
	mockBundleFetcher
}

func (*rescuedSuccessFetcher) BundleFromName(_ context.Context, _ name.Reference, _ []remote.Option) (fetcher.BundleResult, error) {
	return fetcher.BundleResult{
		Bundles:  []*bundle.Bundle{{}},
		Hash:     &v1.Hash{Algorithm: "sha256", Hex: "abc"},
		Attempts: 3,
		Trail: []fetcher.AttemptOutcome{
			{Reason: fetcher.KindTimeout, Step: fetcher.StepDescriptor},
			{Reason: fetcher.KindTimeout, Step: fetcher.StepDescriptor},
		},
	}, nil
}

// TestValidateLogsAttemptTrailOnRescuedSuccess verifies that a fetch which
// succeeded only after earlier failures surfaces those failures on the success
// line, so a retry-rescued success does not hide them.
func TestValidateLogsAttemptTrailOnRescuedSuccess(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &rescuedSuccessFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}
	provider.Validate(context.Background(), request)

	fetched := lastLogLine(t, &buf, "validate: fetched OCI bundles")
	require.NotNil(t, fetched, "expected a fetch success log line")
	assert.InDelta(t, 3.0, fetched["attempts"], 0.0001)
	assert.Equal(t, "timeout:descriptor,timeout:descriptor", fetched["attempt_trail"])
}

// TestValidateOmitsAttemptTrailOnFirstAttemptSuccess verifies the common case:
// a first-attempt success reports attempts=1 and no attempt_trail, so the field
// stays off the success path when there is nothing to surface.
func TestValidateOmitsAttemptTrailOnFirstAttemptSuccess(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	request := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName},
		},
	}
	provider.Validate(context.Background(), request)

	fetched := lastLogLine(t, &buf, "validate: fetched OCI bundles")
	require.NotNil(t, fetched, "expected a fetch success log line")
	assert.InDelta(t, 1.0, fetched["attempts"], 0.0001)
	assert.NotContains(t, fetched, "attempt_trail",
		"a first-attempt success must not carry an attempt_trail field")
}
