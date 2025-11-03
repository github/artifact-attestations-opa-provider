package cainjector

import (
	"encoding/base64"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func loadTestCert(t *testing.T, name string) []byte {
	certPath := filepath.Join("testdata", name+".pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read test certificate %s: %v", certPath, err)
	}
	return data
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
	propagationDelay = 0 // speed up tests

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

func encode(valid1 []byte) string {
	return base64.StdEncoding.EncodeToString(valid1)
}
