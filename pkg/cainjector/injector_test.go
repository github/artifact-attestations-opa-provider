package cainjector

import (
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
		Name     string
		Cert0    []byte
		Cert1    []byte
		Expected []byte
		ErrorMsg string
	}{
		{
			Name:     "Append to empty bundle",
			Cert0:    nil,
			Cert1:    valid1,
			Expected: valid1,
		},
		{
			Name:     "Empty bundles",
			Cert0:    nil,
			Cert1:    nil,
			ErrorMsg: "resulting CA bundle is empty",
		},
		{
			Name:     "Append empty bundle",
			Cert0:    nil,
			Cert1:    valid1,
			Expected: valid1,
		},
		{
			Name:     "Adds new certificates",
			Cert0:    valid1,
			Cert1:    valid2,
			Expected: append(valid1, valid2...),
		},
		{
			Name:     "Removes expired certificates",
			Cert0:    append(valid1, expired...),
			Cert1:    valid2,
			Expected: append(valid1, valid2...),
		},
		{
			Name:     "Remove duplicate certificates in one bundle",
			Cert0:    append(valid1, valid1...),
			Cert1:    valid2,
			Expected: append(valid1, valid2...),
		},
		{
			Name:     "Remove duplicate certificates across bundles",
			Cert0:    valid1,
			Cert1:    valid1,
			Expected: valid1,
		},
		{
			Name:     "Does not append expired certificates",
			Cert0:    valid1,
			Cert1:    expired,
			Expected: valid1,
		},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			result, err := mergeCertBundles(test.Cert0, test.Cert1)
			if test.ErrorMsg != "" {
				require.ErrorContains(t, err, test.ErrorMsg)
			}

			if test.Expected != nil {
				require.Equal(t, test.Expected, result)
			}
		})
	}
}
