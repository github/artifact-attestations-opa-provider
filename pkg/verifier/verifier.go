package verifier

import (
	_ "embed"
	"encoding/hex"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Verifier struct {
	c  *tuf.Client
	tr *root.TrustedRoot
	vo []verify.VerifierOption
}

const (
	tufRootPGI = "https://tuf-repo-cdn.sigstore.dev"
	tufRootGH  = "https://tuf-repo.github.com"
	defaultTR  = "trusted_root.json"
)

//go:embed embed/tuf-repo.github.com/root.json
var githubRoot []byte

func New(rb []byte, tr, tgt string, vo []verify.VerifierOption) (*Verifier, error) {
	var v Verifier
	var b []byte
	var err error

	v.c, err = tuf.New(&tuf.Options{
		Root:              rb,
		RepositoryBaseURL: tr,
		DisableLocalCache: true,
	})
	if err != nil {
		return nil, err
	}
	if b, err = v.c.GetTarget(tgt); err != nil {
		return nil, err
	}
	if v.tr, err = root.NewTrustedRootFromJSON(b); err != nil {
		return nil, err
	}
	v.vo = vo

	return &v, nil
}

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
