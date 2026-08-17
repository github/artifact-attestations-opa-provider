package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

func (*mockBundleFetcher) BundleFromName(_ context.Context, ref name.Reference, _ []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
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
		{
			image: brokenImageName,
			error: "error_fetching_bundle_unknown",
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

// erroringVerifier always fails verification, used to exercise the
// request-level system error path.
type erroringVerifier struct{}

func (*erroringVerifier) Verify(_ []*bundle.Bundle, _ *v1.Hash) ([]*verify.VerificationResult, error) {
	return nil, errors.New("verification blew up")
}

// barrierBundleFetcher rendezvouses the first `width` concurrent fetches at a
// gate before letting any of them proceed. If the outer per-image loop runs
// serially, fewer than `width` fetches ever arrive, the gate never opens and
// the call blocks -- letting a test deterministically distinguish serial from
// parallel execution without relying on timing. It also records the peak
// number of simultaneous in-flight fetches.
type barrierBundleFetcher struct {
	mockBundleFetcher

	width int

	mu          sync.Mutex
	inFlight    int
	maxInFlight int
	arrived     int
	gateClosed  bool
	gate        chan struct{}
}

func newBarrierBundleFetcher(width int) *barrierBundleFetcher {
	return &barrierBundleFetcher{width: width, gate: make(chan struct{})}
}

func (b *barrierBundleFetcher) BundleFromName(ctx context.Context, ref name.Reference, opts []remote.Option) ([]*bundle.Bundle, *v1.Hash, error) {
	b.mu.Lock()
	b.inFlight++
	if b.inFlight > b.maxInFlight {
		b.maxInFlight = b.inFlight
	}
	b.arrived++
	if b.arrived >= b.width && !b.gateClosed {
		b.gateClosed = true
		close(b.gate)
	}
	b.mu.Unlock()

	// Block until at least `width` fetches have arrived concurrently.
	<-b.gate

	res, h, err := b.mockBundleFetcher.BundleFromName(ctx, ref, opts)

	b.mu.Lock()
	b.inFlight--
	b.mu.Unlock()

	return res, h, err
}

func (b *barrierBundleFetcher) MaxInFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxInFlight
}

// validateWithTimeout runs Validate on a goroutine and fails the test if it
// does not return within d, converting a barrier deadlock (serial execution)
// into a clear failure instead of a hung test binary.
func validateWithTimeout(t *testing.T, p *Provider, req *externaldata.ProviderRequest, d time.Duration) *externaldata.ProviderResponse {
	t.Helper()
	ch := make(chan *externaldata.ProviderResponse, 1)
	go func() {
		ch <- p.Validate(context.Background(), req)
	}()
	select {
	case resp := <-ch:
		return resp
	case <-time.After(d):
		t.Fatal("Validate did not complete in time; images were not processed concurrently")
		return nil
	}
}

func TestWithConcurrency(t *testing.T) {
	v := &mockVerifier{}
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}

	// Default is serial.
	assert.Equal(t, 1, New(v, kc, bf).concurrency)
	assert.Equal(t, 4, New(v, kc, bf, WithConcurrency(4)).concurrency)
	// Values below 1 are clamped back to serial.
	assert.Equal(t, 1, New(v, kc, bf, WithConcurrency(0)).concurrency)
	assert.Equal(t, 1, New(v, kc, bf, WithConcurrency(-3)).concurrency)
}

// TestValidateConcurrentMatchesSerial ensures parallel per-image validation
// produces the same ordered results as the serial default.
func TestValidateConcurrentMatchesSerial(t *testing.T) {
	kc := &mockKeyChainProvider{}
	bf := &mockBundleFetcher{}
	v := &mockVerifier{}

	req := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName, "ghcr.io/example/unsigned", brokenImageName, "foo+bar"},
		},
	}

	serial := New(v, kc, bf).Validate(context.Background(), req)
	concurrent := New(v, kc, bf, WithConcurrency(4)).Validate(context.Background(), req)

	require.Len(t, serial.Response.Items, 4)
	require.Len(t, concurrent.Response.Items, len(serial.Response.Items))
	assert.Empty(t, serial.Response.SystemError)
	assert.Empty(t, concurrent.Response.SystemError)

	for i := range serial.Response.Items {
		assert.Equal(t, serial.Response.Items[i].Key, concurrent.Response.Items[i].Key)
		assert.Equal(t, serial.Response.Items[i].Error, concurrent.Response.Items[i].Error)
	}

	// Ordering is preserved and each key maps to its expected outcome.
	assert.Equal(t, validImageName, concurrent.Response.Items[0].Key)
	assert.Equal(t, "invalid_signature", concurrent.Response.Items[0].Error)
	assert.Equal(t, "image_unsigned", concurrent.Response.Items[1].Error)
	assert.Equal(t, "error_fetching_bundle_unknown", concurrent.Response.Items[2].Error)
	assert.Equal(t, "invalid_reference", concurrent.Response.Items[3].Error)
}

// TestValidateProcessesImagesConcurrently proves the outer per-image loop runs
// in parallel: all images must reach the fetcher's barrier simultaneously.
func TestValidateProcessesImagesConcurrently(t *testing.T) {
	const n = 4
	bf := newBarrierBundleFetcher(n)
	p := New(&mockVerifier{}, &mockKeyChainProvider{}, bf, WithConcurrency(n))

	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("ghcr.io/example/image-%d", i)
	}
	req := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: keys},
	}

	resp := validateWithTimeout(t, p, req, 5*time.Second)
	require.NotNil(t, resp)
	assert.Len(t, resp.Response.Items, n)
	assert.Equal(t, n, bf.MaxInFlight())
}

// TestValidateBoundsConcurrency verifies the worker pool never exceeds the
// configured limit even when the request has more images than the limit.
func TestValidateBoundsConcurrency(t *testing.T) {
	const limit = 2
	const keys = 4
	bf := newBarrierBundleFetcher(limit)
	p := New(&mockVerifier{}, &mockKeyChainProvider{}, bf, WithConcurrency(limit))

	imageKeys := make([]string, keys)
	for i := range imageKeys {
		imageKeys[i] = fmt.Sprintf("ghcr.io/example/image-%d", i)
	}
	req := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request:    externaldata.Request{Keys: imageKeys},
	}

	resp := validateWithTimeout(t, p, req, 5*time.Second)
	require.NotNil(t, resp)
	assert.Len(t, resp.Response.Items, keys)
	// The pool reaches, but never exceeds, the configured limit.
	assert.Equal(t, limit, bf.MaxInFlight())
}

// TestValidateConcurrentSystemError ensures a verification error still yields a
// request-level system error response when images are processed in parallel.
func TestValidateConcurrentSystemError(t *testing.T) {
	p := New(&erroringVerifier{}, &mockKeyChainProvider{}, &mockBundleFetcher{}, WithConcurrency(4))

	req := &externaldata.ProviderRequest{
		APIVersion: apiVersion,
		Kind:       "ProviderRequest",
		Request: externaldata.Request{
			Keys: []string{validImageName, validImageName},
		},
	}

	resp := p.Validate(context.Background(), req)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Response.SystemError)
	assert.Empty(t, resp.Response.Items)
}
