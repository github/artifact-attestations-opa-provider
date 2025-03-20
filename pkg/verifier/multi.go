package verifier

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// PublicGoodIssuer is the organization name for certificates
	// issued via PGI Sigstore.
	PublicGoodIssuer = "sigstore.dev"
	// GitHubIssuer is the organization name for certificates
	// issued via GitHub's Sigstore instance.
	GitHubIssuer = "GitHub, Inc."
)

// Multi is a Verifier that knows about multiple trust roots and inspects
// the bundle to select the correct trust root for each provided bundle.
type Multi struct {
	V map[string]*Verifier
}

// NewMulti initializes the multi verifier with a map of Issuer org to
// a Verifier.
func NewMulti(v map[string]*Verifier) *Multi {
	return &Multi{
		V: v,
	}
}

// Verify iterates over each bundle and selects the correct verifier
// based on the certificate's issuer. Bundles with unknown certificate
// issuers are ignored.
func (m *Multi) Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error) {
	var res = []*verify.VerificationResult{}

	for _, b := range bundles {
		var r *verify.VerificationResult
		var v *Verifier
		var iss string
		var err error

		if iss, err = getIssuer(b); err != nil {
			fmt.Printf("failed to extract issuer, skipping\n")
			continue
		}

		if v = m.V[iss]; v == nil {
			fmt.Printf("skipping %s\n", iss)

			// No configured verifier for this issuer
			continue
		}

		if r, err = v.VerifyOne(b, h); err == nil {
			res = append(res, r)
		} else {
			fmt.Println(err)
		}
	}

	return res, nil
}

// getIssuer extracts the certificate from the bundle and returns the
// organization name that issued the certificate.
func getIssuer(b *bundle.Bundle) (string, error) {
	var vc verify.VerificationContent
	var c *x509.Certificate
	var err error

	if vc, err = b.VerificationContent(); err != nil {
		return "", err
	}
	if c = vc.Certificate(); c == nil {
		return "", err
	}

	if len(c.Issuer.Organization) != 1 {
		return "", fmt.Errorf("expected 1 issuer, found %d", len(c.Issuer.Organization))
	}

	return c.Issuer.Organization[0], nil
}
