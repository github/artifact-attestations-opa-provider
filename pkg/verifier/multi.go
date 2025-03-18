package verifier

import (
	"crypto/x509"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	PublicGoodIssuer = "sigstore.dev"
	GitHubIssuer     = "GitHub, Inc."
)

type Multi struct {
	V map[string]*Verifier
}

func NewMulti(v map[string]*Verifier) *Multi {
	return &Multi{
		V: v,
	}
}

func (m *Multi) Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error) {
	var res = []*verify.VerificationResult{}

	for _, b := range bundles {
		var r *verify.VerificationResult
		var v *Verifier
		var iss string
		var err error

		if iss, err = getIssuer(b); err != nil {
			fmt.Printf("skipping 1\n")
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
