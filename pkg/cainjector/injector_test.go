package cainjector

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadTestCert(t *testing.T, name string) []byte {
	path := filepath.Join("testdata", name+".pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test certificate %s: %v", path, err)
	}
	return data
}

func TestMergeCertBundles(t *testing.T) {
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

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			result, err := mergeAndEncode(test.b64Bundle, test.additionalBundle)
			if test.ErrorMsg != "" {
				require.ErrorContains(t, err, test.ErrorMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.Expected, result)
			}

		})
	}
}

func encode(valid1 []byte) string {
	return base64.StdEncoding.EncodeToString(valid1)
}
