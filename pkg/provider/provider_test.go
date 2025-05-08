package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
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

func (*mockBundleFetcher) BundleFromName(ref name.Reference, _ []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	if mb, ok := bundles[ref.Name()]; ok {
		var b bundle.Bundle
		err := b.UnmarshalJSON([]byte(mb.bundle))
		if err != nil {
			return nil, nil, err
		}
		h := v1.Hash{
			Algorithm: "sha256",
			Hex:       mb.hash,
		}
		return []*bundle.Bundle{&b}, &h, nil
	}

	return nil, nil, nil
}

func (*mockBundleFetcher) GetRemoteOptions(_ context.Context, _ authn.Keychain) []remote.Option {
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
	assert.Equal(t, "", response.Response.SystemError)
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
	assert.Equal(t, "", response.Response.SystemError)
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
	assert.True(t, strings.HasSuffix(response.Response.Items[0].Error, "_unsigned"))
	assert.Equal(t, "", response.Response.SystemError)
}

func TestInvalid(t *testing.T) {
	v, err := verifier.GHVerifier("")
	require.NoError(t, err)
	assert.NotNil(t, v)
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	provider := New(v, kc, bf)

	tests := []struct {
		image       string
		errorPrefix string
	}{
		{
			image:       "foo+bar",
			errorPrefix: "ERROR: ParseReference",
		},
		{
			image:       brokenImageName,
			errorPrefix: "ERROR: FromBundle",
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
		assert.Empty(t, response.Response.Items)
		assert.True(t, strings.HasPrefix(response.Response.SystemError, tc.errorPrefix))
	}
}
