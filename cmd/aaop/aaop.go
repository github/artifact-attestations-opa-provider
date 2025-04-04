package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/github/artifact-attestations-opa-provider/pkg/authn"
	"github.com/github/artifact-attestations-opa-provider/pkg/provider"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
)

var (
	noPGI       = flag.Bool("no-public-good", false, "disable public good sigstore instance")
	certsDir    = flag.String("certs", "", "Directory to where TLS certs are stored")
	trustDomain = flag.String("trust-domain", "", "trust domain to use")
	tufRepo     = flag.String("tuf-repo", "", "URL to TUF repository")
	tufRoot     = flag.String("tuf-root", "", "Path to a root.json used to initialize TUF repository")
	ns          = flag.String("namespace", "", "namespace the pod runs in")
	ips         = flag.String("image-pull-secret", "", "the imagePullSecret to use for private registrires")
	port        = flag.String("port", "8080", "port to listen to")
)

const (
	certName = "tls.crt"
	keyName  = "tls.key"
)

type transport struct {
	p *provider.Provider
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
}

func main() {
	var kc *authn.KeyChainProvider
	var v provider.Verifier
	var err error

	flag.Parse()

	if *tufRepo != "" && *tufRoot != "" {
		v = loadCustomVerifier(*tufRepo, *tufRoot, *trustDomain)
	} else {
		v = loadVerifiers(!*noPGI, *trustDomain)
	}

	kc = authn.NewKeyChainProvider(*ns, []string{*ips})
	var p = provider.New(v, kc)
	var t = transport{
		p: p,
	}

	var srv = &http.Server{
		Addr:              fmt.Sprintf(":%s", *port),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	http.HandleFunc("/", t.validate)
	var cf = filepath.Join(*certsDir, certName)
	var kf = filepath.Join(*certsDir, keyName)

	log.Println("starting server...")
	if err = srv.ListenAndServeTLS(cf, kf); err != nil {
		log.Fatalf("failed to start HTTP server: %v", err)
	}
}

// loadCustomVerifier loads a user provided TUF root.
// Currently only verificatoin options with RFC3161 signed timestamps
// are supported.
func loadCustomVerifier(repo, root, td string) provider.Verifier {
	var rb []byte
	var v *verifier.Verifier
	var vo = []verify.VerifierOption{
		verify.WithSignedTimestamps(1),
	}
	var err error

	if rb, err = os.ReadFile(root); err != nil {
		log.Fatalf("failed to load verifier: %v", err)
	}

	if v, err = verifier.New(rb, repo, td, vo); err != nil {
		log.Fatalf("failed to create verifier: %v", err)
	}

	return v
}

// loadVerfiers returns the default verifiers. If pgi is true and tr is
// the empty string, pgi and gh verifiers are returned.
// if the provided trust domain is set, only gh verifier is returend,
// with the set trust domain.
func loadVerifiers(pgi bool, td string) provider.Verifier {
	var mv = verifier.Multi{
		V: map[string]*verifier.Verifier{},
	}
	var v *verifier.Verifier
	var err error

	// only load PGI if no tenant's trust domain is selected
	if pgi && td == "" {
		if v, err = verifier.PGIVerifier(); err != nil {
			log.Fatalf("failed to load PGI verifier: %v", err)
		}
		mv.V[verifier.PublicGoodIssuer] = v
		log.Println("loaded verifier for public good Sigstore")
	}

	if v, err = verifier.GHVerifier(td); err != nil {
		log.Fatalf("failed to load GitHub verifier: %v", err)
	}
	mv.V[verifier.GitHubIssuer] = v
	if td == "" {
		td = "dotcom"
	}
	log.Printf("loaded verifier for GitHub Sigstore: %s", td)

	return &mv
}

// validate intercepts an external data request from OPA Gatekeeper to
// validate a pod.
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

	resp = t.p.Validate(r.Context(), &providerRequest)

	sendResponse(w, resp)
}

func sendResponse(w http.ResponseWriter, r *externaldata.ProviderResponse) {
	var msg = fmt.Sprintf("writing response: items %d", len(r.Response.Items))
	if r.Response.SystemError != "" {
		msg = fmt.Sprintf("%s, systemerror '%s'",
			msg,
			r.Response.SystemError)
	}
	log.Print(msg)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(r); err != nil {
		log.Printf("ERROR: failed to write response: %v", err)
	}
}
