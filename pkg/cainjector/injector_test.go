package cainjector

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

func loadTestCert(t *testing.T, name string) []byte {
	certPath := filepath.Join("testdata", name+".pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read test certificate %s: %v", certPath, err)
	}
	return data
}

func disablePropagationDelay(t *testing.T) {
	t.Helper()
	original := propagationDelay
	propagationDelay = 0
	t.Cleanup(func() {
		propagationDelay = original
	})
}

func TestUpdateCABundle(t *testing.T) {
	// Load certificates from testdata
	expired := loadTestCert(t, "expired")
	valid1 := loadTestCert(t, "valid1")
	valid2 := loadTestCert(t, "valid2")

	cases := []struct {
		Name             string
		b64Bundle        string
		additionalBundle []byte
		Expected         string
		ErrorMsg         string
	}{
		{
			Name:             "Append to empty bundle",
			b64Bundle:        "",
			additionalBundle: valid1,
			Expected:         encode(valid1),
		},
		{
			Name:             "Empty bundles",
			b64Bundle:        "",
			additionalBundle: nil,
			ErrorMsg:         "resulting CA bundle is empty",
		},
		{
			Name:             "Append empty bundle",
			b64Bundle:        "",
			additionalBundle: valid1,
			Expected:         encode(valid1),
		},
		{
			Name:             "Adds new certificates",
			b64Bundle:        encode(valid1),
			additionalBundle: valid2,
			Expected:         encode(append(valid1, valid2...)),
		},
		{
			Name:             "Retains unexpired certificates removed from mounted bundle",
			b64Bundle:        encode(append(valid1, valid2...)),
			additionalBundle: valid2,
			Expected:         encode(append(valid1, valid2...)),
		},
		{
			Name:             "Removes expired certificates",
			b64Bundle:        encode(append(valid1, expired...)),
			additionalBundle: valid2,
			Expected:         encode(append(valid1, valid2...)),
		},
		{
			Name:             "Remove duplicate certificates in one bundle",
			b64Bundle:        encode(append(valid1, valid1...)),
			additionalBundle: valid2,
			Expected:         encode(append(valid1, valid2...)),
		},
		{
			Name:             "Remove duplicate certificates across bundles",
			b64Bundle:        encode(valid1),
			additionalBundle: valid1,
			Expected:         encode(valid1),
		},
		{
			Name:             "Does not append expired certificates",
			b64Bundle:        encode(valid1),
			additionalBundle: expired,
			Expected:         encode(valid1),
		},
	}
	err := v1beta1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	disablePropagationDelay(t)

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			client := fake.NewSimpleDynamicClient(scheme.Scheme, &v1beta1.Provider{
				ObjectMeta: v1.ObjectMeta{
					Name: "artifact-attestations-opa-provider",
				},
				Spec: v1beta1.ProviderSpec{
					CABundle: test.b64Bundle,
				},
			})

			caPath := path.Join(t.TempDir(), "ca.crt")
			require.NoError(t, os.WriteFile(caPath, test.additionalBundle, 0600))

			err = UpdateCABundle(t.Context(), client, caPath)
			if test.ErrorMsg != "" {
				require.ErrorContains(t, err, test.ErrorMsg)
			} else {
				require.NoError(t, err)

				rawProvider, err := client.Resource(schema.GroupVersionResource{
					Group:    "externaldata.gatekeeper.sh",
					Version:  "v1beta1",
					Resource: "providers",
				}).Get(t.Context(), "artifact-attestations-opa-provider", v1.GetOptions{})
				require.NoError(t, err)

				var provider v1beta1.Provider
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(rawProvider.UnstructuredContent(), &provider)
				require.NoError(t, err)
				require.Equal(t, test.Expected, provider.Spec.CABundle)
			}
		})
	}
}

func TestStartUpdatesImmediately(t *testing.T) {
	disablePropagationDelay(t)

	valid := loadTestCert(t, "valid1")
	err := v1beta1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	client := fake.NewSimpleDynamicClient(scheme.Scheme, &v1beta1.Provider{
		ObjectMeta: v1.ObjectMeta{
			Name: "artifact-attestations-opa-provider",
		},
	})

	caPath := path.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caPath, valid, 0600))

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	require.NoError(t, Start(ctx, client, caPath, time.Hour))

	rawProvider, err := client.Resource(schema.GroupVersionResource{
		Group:    "externaldata.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "providers",
	}).Get(t.Context(), "artifact-attestations-opa-provider", v1.GetOptions{})
	require.NoError(t, err)

	var provider v1beta1.Provider
	require.NoError(t,
		runtime.DefaultUnstructuredConverter.FromUnstructured(rawProvider.UnstructuredContent(), &provider))
	require.Equal(t, encode(valid), provider.Spec.CABundle)
}

func TestStartRejectsNonPositiveInterval(t *testing.T) {
	err := Start(t.Context(), nil, "", 0)
	require.EqualError(t, err, "CA bundle refresh interval must be greater than zero")
}

func TestStartTimesOutStalledRequests(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				caPath := filepath.Join(t.TempDir(), "ca.crt")
				require.NoError(t, os.WriteFile(caPath, loadTestCert(t, "valid1"), 0600))

				client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
					if req.Method != method {
						time.Sleep(5 * time.Second)
						return providerResponse(""), nil
					}
					if _, ok := req.Context().Deadline(); !ok {
						return nil, errors.New("request has no deadline")
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				})

				started := time.Now()
				err := Start(t.Context(), client, caPath, time.Hour)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Equal(t, 30*time.Second, time.Since(started))
				require.NoError(t, t.Context().Err())
			})
		})
	}
}

func TestStartRetriesAfterTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		valid := loadTestCert(t, "valid1")
		caPath := filepath.Join(t.TempDir(), "ca.crt")
		require.NoError(t, os.WriteFile(caPath, valid, 0600))

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		requests := make(chan context.Context, 3)
		var calls int
		client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
			calls++
			requests <- req.Context()
			if calls == 2 {
				if _, ok := req.Context().Deadline(); !ok {
					return nil, errors.New("request has no deadline")
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			}
			return providerResponse(encode(valid)), nil
		})

		require.NoError(t, Start(ctx, client, caPath, time.Hour))
		require.Len(t, requests, 1)
		initialRequest := <-requests

		time.Sleep(time.Hour)
		synctest.Wait()
		require.Len(t, requests, 1)
		timedOutRequest := <-requests
		_, bounded := timedOutRequest.Deadline()
		require.True(t, bounded, "periodic refresh must have its own deadline")
		require.NoError(t, timedOutRequest.Err())

		time.Sleep(30 * time.Second)
		synctest.Wait()
		require.ErrorIs(t, timedOutRequest.Err(), context.DeadlineExceeded)
		require.NoError(t, ctx.Err())

		time.Sleep(time.Hour - 30*time.Second)
		synctest.Wait()
		require.Len(t, requests, 1, "the next interval must retry after the timeout")
		retriedRequest := <-requests
		require.NoError(t, ctx.Err())
		require.ErrorIs(t, initialRequest.Err(), context.Canceled)
		require.ErrorIs(t, retriedRequest.Err(), context.Canceled)
	})
}

func TestStartHonorsParentCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(time.Second, cancel)

		client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})

		started := time.Now()
		err := Start(ctx, client, "", time.Hour)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, time.Second, time.Since(started))
	})
}

func TestStartHonorsParentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()

		client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})

		started := time.Now()
		err := Start(ctx, client, "", time.Hour)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, time.Second, time.Since(started))
	})
}

func TestRefreshLoopRetriesAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	tick := make(chan time.Time)
	updated := make(chan struct{})
	var calls atomic.Int64
	update := func(context.Context) error {
		call := calls.Add(1)
		updated <- struct{}{}
		if call == 1 {
			return errors.New("transient failure")
		}
		return nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshLoop(ctx, tick, update)
	}()

	tick <- time.Time{}
	<-updated
	tick <- time.Time{}
	<-updated
	require.Equal(t, int64(2), calls.Load())

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not stop after context cancellation")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(t *testing.T, roundTrip roundTripFunc) *dynamic.DynamicClient {
	t.Helper()
	client, err := dynamic.NewForConfig(&rest.Config{
		Host:      "https://kubernetes.example",
		Transport: roundTrip,
	})
	require.NoError(t, err)
	return client
}

func providerResponse(bundle string) *http.Response {
	body := fmt.Sprintf(
		`{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"Provider","metadata":{"name":"artifact-attestations-opa-provider"},"spec":{"caBundle":%q}}`,
		bundle,
	)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func encode(valid1 []byte) string {
	return base64.StdEncoding.EncodeToString(valid1)
}
