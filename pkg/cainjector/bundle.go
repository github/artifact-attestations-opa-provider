// This file is based on work from The cert-manager Authors licensed under the Apache License, Version 2.0;
// See https://github.com/cert-manager/cert-manager/tree/f7545b42e8444d89d8053dadde0bb68270cabc3e/internal/cainjector/bundle

package cainjector

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"k8s.io/utils/set"
)

// ErrNoPEMData is returned when the given data contained no PEM.
var ErrNoPEMData = errors.New("no PEM data was found in given input")

// AppendCertificatesToBundle will append the provided certificates to the
// provided bundle, if the certificate already exists in the bundle then it is
// not re-added.
//
// Additionally expired certificates are removed from the bundle.
func appendCertificatesToBundle(bundle []byte, additional []byte) ([]byte, error) {
	certificatesFromBundle, err := decodeMultipleCerts(bundle)
	if err != nil && len(bundle) != 0 {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	certificatesToMerge, err := decodeMultipleCerts(additional)
	if err != nil && len(additional) != 0 {
		return nil, fmt.Errorf("failed to parse additional certificates: %w", err)
	}

	certificatesSeen := set.New[string]()
	certificatesMerged := make([]*x509.Certificate, 0, len(certificatesFromBundle)+len(certificatesToMerge))

	// We delete expired certificates from the bundle, for this we will
	// repeatedly need the current time
	now := time.Now()

	// Merge in all certificates that already exist in the bundle
	for _, certificate := range certificatesFromBundle {
		raw := string(certificate.Raw)
		if !certificatesSeen.Has(raw) && !now.After(certificate.NotAfter) {
			certificatesMerged = append(certificatesMerged, certificate)
			certificatesSeen.Insert(raw)
		}
	}

	// Merge in all additional certificates
	for _, certificate := range certificatesToMerge {
		raw := string(certificate.Raw)
		if !certificatesSeen.Has(raw) && !now.After(certificate.NotAfter) {
			certificatesMerged = append(certificatesMerged, certificate)
			certificatesSeen.Insert(raw)
		}
	}

	// Build the chain
	buff := bytes.NewBuffer([]byte{})
	for _, certificate := range certificatesMerged {
		if err := pem.Encode(buff, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, fmt.Errorf("failed encode certificate in PEM format: %w", err)
		}
	}

	return buff.Bytes(), nil
}

func decodeMultipleCerts(certBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		var err error

		// decode the tls certificate pem
		block, certBytes, err = safeDecodeInternal(certBytes)
		if err != nil {
			if errors.Is(err, ErrNoPEMData) {
				break
			}

			return nil, err
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing X.509 certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("error decoding certificate PEM block: no valid certificates found")
	}

	return certs, nil
}

const maxSize = 330000

func safeDecodeInternal(b []byte) (*pem.Block, []byte, error) {
	if len(b) > maxSize {
		return nil, b, fmt.Errorf("PEM data exceeds maximum size of %d bytes", maxSize)
	}

	block, rest := pem.Decode(b)
	if block == nil {
		return nil, rest, ErrNoPEMData
	}

	return block, rest, nil
}
