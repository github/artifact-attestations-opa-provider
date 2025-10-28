// This file is based on work from The cert-manager Authors licensed under the Apache License, Version 2.0;
// See https://github.com/cert-manager/cert-manager/tree/f7545b42e8444d89d8053dadde0bb68270cabc3e/internal/cainjector/bundle

package cainjector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func loadTestCert(t *testing.T, name string) []byte {
	path := filepath.Join("testdata", name+".pem")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test certificate %s: %v", path, err)
	}
	return data
}

func TestAppendCertificatesToBundle(t *testing.T) {
	// Load certificates from testdata
	expired := loadTestCert(t, "expired")
	valid1 := loadTestCert(t, "valid1")
	valid2 := loadTestCert(t, "valid2")

	cases := []struct {
		Name       string
		Bundle     []byte
		Additional []byte
		Expected   []byte
		ExpectErr  bool
	}{
		{
			Name:       "append_to_empty_bundle",
			Bundle:     nil,
			Additional: valid1,
			Expected:   valid1,
		},
		{
			Name:       "append_to_non_empty_bundle",
			Bundle:     valid1,
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "removes_expired_certificates",
			Bundle:     joinPEM(valid1, expired),
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "removes_duplicate_certificates",
			Bundle:     joinPEM(valid1, valid1),
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "does_not_append_existing_certificates",
			Bundle:     joinPEM(valid1),
			Additional: valid1,
			Expected:   joinPEM(valid1),
		},
		{
			Name:       "does_not_append_expired_certificates",
			Bundle:     joinPEM(valid1),
			Additional: expired,
			Expected:   joinPEM(valid1),
		},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			result, err := appendCertificatesToBundle(test.Bundle, test.Additional)

			if (err != nil) != test.ExpectErr {
				t.Fatalf("unexpected error, expected error %t, got %q", test.ExpectErr, err)
			}

			if !bytes.Equal(result, test.Expected) {
				t.Fatalf("unexpected result, expected %q, got %q", test.Expected, result)
			}
		})
	}
}

func joinPEM(first []byte, rest ...[]byte) []byte {
	for _, b := range rest {
		first = append(first, b...)
	}

	return first
}
