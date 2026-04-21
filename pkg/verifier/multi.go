package verifier

import (
	"log/slog"

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

// Multi is a Verifier that knows about multiple trust roots.
// During verification each trust root are tried until a successful
// verification is reached.
type Multi struct {
	V []*Verifier
}

// NewMulti initializes a verifier with an ordered list of verifiers.
func NewMulti(v []*Verifier) *Multi {
	var m = make([]*Verifier, len(v))

	copy(m, v)
	return &Multi{
		V: m,
	}
}

// Verify iterates over each bundle, and verifies the bundle against
// all known trust roots. If a successful verification occurs, no other
// trust roots are tried.
func (m *Multi) Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error) {
	var res = []*verify.VerificationResult{}
	var err error

	for _, b := range bundles {
		var r *verify.VerificationResult

		for _, v := range m.V {
			if r, err = v.VerifyOne(b, h); err == nil {
				res = append(res, r)
				// skip rest of verifiers if verified
				break
			}
		}

		if r == nil {
			subjects, subjectsErr := bundleSubjects(b)
			attrs := []any{
				"image_digest", h.Hex,
				"error", err,
				"bundle_subjects", subjects,
			}
			if subjectsErr != nil {
				attrs = append(attrs, "bundle_subjects_error", subjectsErr)
			}

			slog.Error("multi: verifying signature failed",
				attrs...)
		}
	}

	return res, nil
}
