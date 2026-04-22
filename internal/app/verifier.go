package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// DotcomTrustDomain is the default one when accessing github.com.
const DotcomTrustDomain = "dotcom"

// VerifierCfg holds the config needed to load all verifiers.
type VerifierCfg struct {
	TufRoot      string
	TufRepo      string
	TufTargets   []string
	TrustDomains []string
	UsePGI       bool
}

// CreateVerifier loads verifiers based on the provided config, and wraps
// them in a multi verifier.
func CreateVerifier(cfg *VerifierCfg) (*verifier.Multi, error) {
	var verifiers = []*verifier.Verifier{}
	var vv []*verifier.Verifier
	var err error

	if cfg.TufRepo != "" && cfg.TufRoot != "" && len(cfg.TufTargets) > 0 {
		if vv, err = LoadCustomVerifier(cfg.TufRepo,
			cfg.TufRoot,
			cfg.TufTargets); err != nil {
			slog.Error("failed to load custom verifier", "error", err)
			return nil, err
		}

		verifiers = append(verifiers, vv...)
	}

	if vv, err = LoadVerifiers(cfg.UsePGI, cfg.TrustDomains); err != nil {
		slog.Error("failed to load verifiers", "error", err)
		return nil, err
	}
	verifiers = append(verifiers, vv...)

	return verifier.NewMulti(verifiers), nil
}

// LoadCustomVerifier loads a user provided TUF root.
// Currently only verification options with RFC3161 signed timestamps
// are supported.
func LoadCustomVerifier(repo, root string, tds []string) ([]*verifier.Verifier, error) {
	var rb []byte
	var verifiers = []*verifier.Verifier{}
	var vo = []verify.VerifierOption{
		verify.WithSignedTimestamps(1),
	}
	var err error

	if rb, err = os.ReadFile(root); err != nil {
		return nil, fmt.Errorf("failed to load verifier: %w", err)
	}

	for _, td := range tds {
		var v *verifier.Verifier

		if v, err = verifier.New(rb, repo, td, vo); err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}

		verifiers = append(verifiers, v)

		slog.Info("loaded verifier",
			"tuf_repo", repo,
			"trust_domain", td)
	}

	if len(verifiers) == 0 {
		return nil, errors.New("no trust root provided")
	}

	return verifiers, nil
}

// LoadVerifiers returns the default verifiers. If pgi is true and tr is
// the empty string, pgi and gh verifiers are returned.
// if the provided trust domain is set, only gh verifier is returned,
// with the set trust domain.
func LoadVerifiers(pgi bool, tds []string) ([]*verifier.Verifier, error) {
	var verifiers = []*verifier.Verifier{}
	var v *verifier.Verifier
	var err error

	if len(tds) == 0 {
		tds = append(tds, DotcomTrustDomain)
	}

	if pgi {
		if v, err = verifier.PGIVerifier(); err != nil {
			return nil, fmt.Errorf("failed to load PGI verifier: %w", err)
		}
		verifiers = append(verifiers, v)
		slog.Info("loaded verifier",
			"instance", "public good Sigstore")
	}

	for _, td := range tds {
		if v, err = verifier.GHVerifier(td); err != nil {
			return nil, fmt.Errorf("failed to load GitHub verifier: %w", err)
		}
		verifiers = append(verifiers, v)

		slog.Info("loaded verifier",
			"instance", "GitHub Sigstore",
			"trust_domain", td)
	}

	return verifiers, nil
}
