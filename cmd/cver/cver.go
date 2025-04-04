package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
)

var (
	img = flag.String("i", "", "image to verify")
)

func main() {
	var mv = &verifier.Multi{
		V: map[string]*verifier.Verifier{},
	}
	var v *verifier.Verifier
	var res []*verify.VerificationResult
	var ref name.Reference
	var remoteOpts = []remote.Option{}
	var b []*bundle.Bundle
	var h *v1.Hash
	var err error

	flag.Parse()

	if *img == "" {
		fmt.Println("no image provided")
	}

	if v, err = verifier.PGIVerifier(); err != nil {
		log.Print(err)
	}

	mv.V[verifier.PublicGoodIssuer] = v

	if v, err = verifier.GHVerifier(""); err != nil {
		log.Print(err)
	}
	mv.V[verifier.GitHubIssuer] = v

	if ref, err = name.ParseReference(*img); err != nil {
		log.Print(err)
	}
	if b, h, err = fetcher.BundleFromName(ref, remoteOpts); err != nil {
		log.Print(err)
	}
	if res, err = mv.Verify(b, h); err != nil {
		log.Print(err)
	}
	for _, r := range res {
		log.Printf("%+v\n", r)
	}
}
