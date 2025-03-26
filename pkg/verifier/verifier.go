package verifier

import (
	_ "embed"
	"encoding/hex"
	"fmt"

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
			fmt.Println(err)
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
	var sev *verify.SignedEntityVerifier
	var digest []byte
	var pb verify.PolicyBuilder
	var err error

	if sev, err = verify.NewSignedEntityVerifier(v.tr, v.vo...); err != nil {
		return nil, err
	}

	if digest, err = hex.DecodeString(h.Hex); err != nil {
		return nil, err
	}

	ap = verify.WithArtifactDigest(h.Algorithm, digest)
	pb = verify.NewPolicy(ap, po...)

	return sev.Verify(b, pb)
}
