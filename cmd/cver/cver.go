package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/internal/app"
	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
)

var (
	img           = flag.String("i", "", "image to verify")
	trustDomains  = flag.String("trust-domains", "", "comma separated list of trust domains for GitHub's TUF repo")
	bundleFile    = flag.String("bundle", "", "path to a sigstore bundle JSON file on disk")
	tufRepo       = flag.String("tuf-repo", "", "URL to custom TUF repository")
	tufRoot       = flag.String("tuf-root", "", "path to root.json for custom TUF repository")
	tufTargets    = flag.String("tuf-targets", "", "comma separated list of targets (trust domains) for custom TUF repo")
	predicateType = flag.String("predicate-type", "", "if set, only retrieve the first attestation whose dev.sigstore.bundle.predicateType annotation matches this value")
)

func main() {
	var v *verifier.Multi
	var res []*verify.VerificationResult
	var ref name.Reference
	var remoteOpts = []remote.Option{}
	var b []*bundle.Bundle
	var h *v1.Hash
	var err error

	flag.Parse()

	fetcher.PredicateType = *predicateType

	if *img == "" && *bundleFile == "" {
		fmt.Println("no image or bundle provided")
		return
	}

	var vCfg = app.VerifierCfg{
		TufRoot: *tufRoot,
		TufRepo: *tufRepo,
		UsePGI:  true,
	}

	if *tufTargets != "" {
		var targets = []string{}
		tmp := strings.Split(*tufTargets, ",")

		for _, t := range tmp {
			candidate := strings.TrimSpace(t)
			if candidate == "" {
				continue
			}
			targets = append(targets, candidate)
		}
		vCfg.TufTargets = targets
	}

	if *trustDomains != "" {
		var tds []string
		tmp := strings.Split(*trustDomains, ",")

		for _, t := range tmp {
			candidate := strings.TrimSpace(t)
			if candidate == "" {
				continue
			}
			tds = append(tds, candidate)
		}
		vCfg.TrustDomains = tds
	}

	if v, err = app.CreateVerifier(&vCfg); err != nil {
		log.Fatalf("failed to create verifier: %v", err)
	}

	if *bundleFile != "" {
		// Load bundle from disk and extract digest from in-toto statement
		bundleBytes, err := os.ReadFile(*bundleFile)
		if err != nil {
			log.Fatalf("failed to read bundle file: %v", err)
		}

		sb := &bundle.Bundle{}
		if err = sb.UnmarshalJSON(bundleBytes); err != nil {
			log.Fatalf("failed to unmarshal bundle: %v", err)
		}

		sc, err := sb.SignatureContent()
		if err != nil {
			log.Fatalf("failed to get signature content: %v", err)
		}

		ec := sc.EnvelopeContent()
		if ec == nil {
			log.Fatal("bundle does not contain dsse envelope")
		}

		stmt, err := ec.Statement()
		if err != nil {
			log.Fatalf("failed to get statement: %v", err)
		}

		subjects := stmt.GetSubject()
		if len(subjects) == 0 {
			log.Fatal("no subjects in statement")
		}

		// Use the first subject's digest to construct the v1.Hash
		digests := subjects[0].GetDigest()
		for alg, hex := range digests {
			h = &v1.Hash{
				Algorithm: alg,
				Hex:       hex,
			}
			break
		}

		b = []*bundle.Bundle{sb}
	} else {
		if ref, err = name.ParseReference(*img); err != nil {
			log.Print(err)
		}
		ctx := context.Background()
		if b, h, err = fetcher.BundleFromName(ctx, ref, remoteOpts); err != nil {
			log.Print(err)
		}
	}

	if res, err = v.Verify(b, h); err != nil {
		log.Print(err)
	}
	for _, r := range res {
		j, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			log.Printf("failed to marshal result: %v", err)
			continue
		}
		fmt.Println(string(j))
	}
}
