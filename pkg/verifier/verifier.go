package verifier

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Verifier verifies Sigstore bundles for OCI images.
type Verifier struct {
	tr root.TrustedMaterial
	vo []verify.VerifierOption
}

const (
	tufRootPGI = "https://tuf-repo-cdn.sigstore.dev"
	tufRootGH  = "https://tuf-repo.github.com"
	defaultTR  = "trusted_root.json"

	// maxBundleSubjects caps the number of subjects included when
	// logging bundle contents. Bundles are attacker-controlled, so
	// we bound this to prevent log amplification.
	maxBundleSubjects = 5
)

//go:embed embed/tuf-repo.github.com/root.json
var githubRoot []byte

// New initializes a new Verifier for the provided TUF repository and
// verifier options. Note that the target for the trusted_root must be
// provided.
func New(rb []byte, tr, tgt string, vo []verify.VerifierOption) (*Verifier, error) {
	var v Verifier
	var opts = &tuf.Options{
		Root:              rb,
		RepositoryBaseURL: tr,
		DisableLocalCache: true,
	}
	var err error

	if v.tr, err = root.NewLiveTrustedRootFromTarget(opts, tgt); err != nil {
		return nil, err
	}
	v.vo = vo

	return &v, nil
}

// PGIVerifier is a helper method to initialized a Verifier for Sigstore
// Public Good Instance with the following verification options:
// * Require SCT.
// * Require at least one transparency log entry.
// * Require at least one observed timestamp.
func PGIVerifier() (*Verifier, error) {
	var vo = []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}

	return New(tuf.DefaultRoot(),
		tufRootPGI,
		defaultTR,
		vo,
	)
}

// GHVerifier is a helper method to initialize a verifier for GitHub's
// Sigstore instance with the following verification options:
// * Require a RFC3161 signed timestamp.
// If the default trust domain is wanted, provide the empty string or
// "dotcom". For other domains, provide the name of the trust domain.
func GHVerifier(td string) (*Verifier, error) {
	var target string
	var vo = []verify.VerifierOption{
		verify.WithSignedTimestamps(1),
	}

	if td == "" || td == "dotcom" {
		target = defaultTR
	} else {
		target = fmt.Sprintf("%s.%s", td, defaultTR)
	}

	return New(githubRoot,
		tufRootGH,
		target,
		vo,
	)
}

// Verify iterates of the provided bundles and returns a set of verification
// results using VerifyOne.
func (v *Verifier) Verify(bundles []*bundle.Bundle, h *v1.Hash) ([]*verify.VerificationResult, error) {
	var res = []*verify.VerificationResult{}
	var err error

	for _, b := range bundles {
		var r *verify.VerificationResult

		if r, err = v.VerifyOne(b, h); err == nil {
			res = append(res, r)
		} else {
			subjects, subjectsErr := bundleSubjects(b)
			attrs := []any{
				"image_digest", h.Hex,
				"error", err,
				"bundle_subjects", subjects,
			}
			if subjectsErr != nil {
				attrs = append(attrs, "bundle_subjects_error", subjectsErr)
			}

			slog.Error("failed to verify signature", attrs...)
		}
	}

	return res, nil
}

// VerifyOne verifies a single bundle against an OCI image's digest.
// No verification of the signer's identity is made.
func (v *Verifier) VerifyOne(b *bundle.Bundle, h *v1.Hash) (*verify.VerificationResult, error) {
	var po = []verify.PolicyOption{
		verify.WithoutIdentitiesUnsafe(),
	}
	var ap verify.ArtifactPolicyOption
	var sv *verify.Verifier
	var digest []byte
	var pb verify.PolicyBuilder
	var err error

	if sv, err = verify.NewVerifier(v.tr, v.vo...); err != nil {
		return nil, err
	}

	if digest, err = hex.DecodeString(h.Hex); err != nil {
		return nil, err
	}

	ap = verify.WithArtifactDigest(h.Algorithm, digest)
	pb = verify.NewPolicy(ap, po...)

	return sv.Verify(b, pb)
}

func bundleSubjects(b *bundle.Bundle) (subjects []string, err error) {
	// There are a few possibilities for nil pointer access to creep in,
	// make sure we never panic on bad input.
	defer func() {
		if r := recover(); r != nil {
			subjects = nil
			err = fmt.Errorf("panic extracting bundle subjects: %v", r)
		}
	}()

	if b == nil || b.Bundle == nil {
		return nil, errors.New("nil bundle")
	}

	sc, err := b.SignatureContent()
	if err != nil {
		return nil, err
	}

	if sc == nil {
		return nil, errors.New("bundle does not contain signature content")
	}

	ec := sc.EnvelopeContent()
	if ec == nil {
		return nil, errors.New("bundle does not contain dsse envelope")
	}

	statement, err := ec.Statement()
	if err != nil {
		return nil, err
	}

	if statement == nil || len(statement.GetSubject()) == 0 {
		return []string{}, nil
	}

	subjects = make([]string, 0, len(statement.GetSubject()))
	for _, s := range statement.GetSubject() {
		if s == nil {
			continue
		}

		if len(s.GetDigest()) == 0 {
			subjects = append(subjects, fmt.Sprintf("%s: <no digest>", s.GetName()))
			continue
		}

		algs := make([]string, 0, len(s.GetDigest()))
		for alg := range s.GetDigest() {
			algs = append(algs, alg)
		}
		slices.Sort(algs)

		pairs := make([]string, 0, len(algs))
		for _, alg := range algs {
			pairs = append(pairs, fmt.Sprintf("%s=%s", alg, s.GetDigest()[alg]))
		}

		subjects = append(subjects, fmt.Sprintf("%s: %s", s.GetName(), strings.Join(pairs, ", ")))
	}

	if len(subjects) > maxBundleSubjects {
		truncated := subjects[:maxBundleSubjects]
		truncated = append(truncated, fmt.Sprintf("... and %d more subjects", len(subjects)-maxBundleSubjects))
		return truncated, nil
	}

	return subjects, nil
}
