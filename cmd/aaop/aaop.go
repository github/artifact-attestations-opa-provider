package main

import (
	"path/filepath"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/github/artifact-attestations-opa-provider/pkg/provider"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
)

var (
	noPGI       = flag.Bool("no-public-good", false, "disable public good sigstore instance")
	trustDomain = flag.String("trust-domain", "", "trust domain to use")
)

const (
	certName = "tls.crt"
	keyName  = "tls.key"
	certsDir = "certs"
)

type transport struct {
	p *provider.Provider
}

func main() {
	var mv = verifier.Multi{
		V: map[string]*verifier.Verifier{},
	}
	var v *verifier.Verifier
	var err error
	flag.Parse()

	fmt.Println("starting server...")

	// only load PGI if no tenant's trust domain is selected
	if !*noPGI && *trustDomain == "" {
		if v, err = verifier.PGIVerifier(); err != nil {
			panic(err)
		}
		mv.V[verifier.PublicGoodIssuer] = v
	}

	if v, err = verifier.GHVerifier(*trustDomain); err != nil {
		panic(err)
	}
	mv.V[verifier.GitHubIssuer] = v

	var p = provider.New(&mv)
	var t = transport{
		p: p,
	}

	srv := &http.Server{
		Addr:              ":8090",
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	http.HandleFunc("/", t.validate)
	var cf = filepath.Join(certsDir, certName)
	var kf = filepath.Join(certsDir, keyName)

	if err := srv.ListenAndServeTLS(cf, kf); err != nil {
		panic(err)
	}
}

func (t *transport) validate(w http.ResponseWriter, r *http.Request) {
	var resp *externaldata.ProviderResponse

	// only accept POST requests
	if r.Method != http.MethodPost {
		sendResponse(w, provider.ErrorResponse("only POST is allowed"))
		return
	}

	// read request body
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		sendResponse(w, provider.ErrorResponse(fmt.Sprintf("unable to read request body: %v", err)))
		return
	}

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		sendResponse(w, provider.ErrorResponse(fmt.Sprintf("unable to unmarshal request body: %v", err)))
		return
	}

	// ctx := req.Context()
	// ro := options.RegistryOptions{}
	// co, err := ro.ClientOpts(ctx)

	fmt.Printf("req: %+v\n", providerRequest)

	resp = t.p.Validate(&providerRequest)

	fmt.Printf("resp: %+v\n", resp)

	sendResponse(w, resp)
}

func sendResponse(w http.ResponseWriter, r *externaldata.ProviderResponse) {
	fmt.Printf("resp: %+v\n", r)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(r); err != nil {
		panic(err)
	}
}
