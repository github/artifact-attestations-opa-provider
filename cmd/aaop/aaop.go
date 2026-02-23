package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/github/artifact-attestations-opa-provider/pkg/authn"
	"github.com/github/artifact-attestations-opa-provider/pkg/cainjector"
	"github.com/github/artifact-attestations-opa-provider/pkg/fetcher"
	"github.com/github/artifact-attestations-opa-provider/pkg/provider"
	"github.com/github/artifact-attestations-opa-provider/pkg/verifier"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

var (
	noPGI          = flag.Bool("no-public-good", false, "disable public good sigstore instance")
	certsDir       = flag.String("certs", "", "Directory to where TLS certs are stored")
	trustDomain    = flag.String("trust-domain", "", "trust domain to use")
	tufRepo        = flag.String("tuf-repo", "", "URL to TUF repository")
	tufRoot        = flag.String("tuf-root", "", "Path to a root.json used to initialize TUF repository")
	ns             = flag.String("namespace", "", "namespace the pod runs in")
	ips            = flag.String("image-pull-secret", "", "the imagePullSecret to use for private registries")
	port           = flag.String("port", "8080", "port to listen to")
	metricsPort    = flag.String("metrics-port", "9090", "port to listen to for metrics")
	updateCABundle = flag.Bool("update-ca-bundle", false, "regularly update the Provider's caBundle field")
)

const (
	certName = "tls.crt"
	keyName  = "tls.key"
)

// DotcomTrustDomain is the default one when accessing github.com.
const DotcomTrustDomain = "dotcom"

type transport struct {
	p *provider.Provider
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	opts := slog.HandlerOptions{Level: slog.LevelInfo}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &opts)))
}

func main() {
	var kc *authn.KeyChainProvider
	var v provider.Verifier
	var err error

	flag.Parse()

	if *tufRepo != "" && *tufRoot != "" {
		if v, err = loadCustomVerifier(*tufRepo,
			*tufRoot,
			*trustDomain); err != nil {
			log.Fatal(err)
		}
	} else {
		if v, err = loadVerifiers(!*noPGI, *trustDomain); err != nil {
			log.Fatal(err)
		}
	}

	// Start the metrics server
	go func() {
		var mm = http.NewServeMux()
		mm.Handle("/metrics", promhttp.Handler())

		var promSrv = &http.Server{
			Addr:              fmt.Sprintf(":%s", *metricsPort),
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			Handler:           mm,
		}
		slog.Info("starting Prometheus metrics server",
			"url", promSrv.Addr)
		if err := promSrv.ListenAndServe(); err != nil {
			log.Fatalf("failed to start metrics server: %v", err)
		}
	}()

	if *updateCABundle {
		client, err := getK8sClient()
		if err != nil {
			log.Fatalf("failed to create Kubernetes client: %v", err)
		}

		if err := cainjector.UpdateCABundle(context.Background(), client, path.Join(*certsDir, "ca.crt")); err != nil {
			log.Fatalf("failed to update CA bundle: %v", err)
		}
	}

	kc = authn.NewKeyChainProvider(*ns, []string{*ips})
	var p = provider.New(v, kc, &fetcher.DefaultBundleFetcher{})
	var t = transport{
		p: p,
	}
	var sm = http.NewServeMux()
	sm.HandleFunc("/", t.validate)
	sm.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Handle signals gracefully to avoid dropping requests during Pod shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var srv = &http.Server{
		Addr:              fmt.Sprintf(":%s", *port),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           sm,
	}

	var cf = filepath.Join(*certsDir, certName)
	var kf = filepath.Join(*certsDir, keyName)

	slog.Info("starting server",
		"url", srv.Addr)

	if err = run(ctx, srv, cf, kf); err != nil {
		stop()
		log.Fatalf("failed to start HTTP server: %v", err)
	}

	slog.Info("shutting down server")
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	if err = srv.Shutdown(ctxShutDown); err != nil {
		cancel()
		stop()
		log.Fatalf("server shutdown failed: %v", err)
	}
	cancel()
	stop()
	slog.Info("server shut down gracefully")
}

// run starts the HTTP server and blocks until either the context has been cancelled
// or ListenAndServeTLS returns an error.
func run(ctx context.Context, srv *http.Server, cf string, kf string) error {
	errChan := make(chan error, 1)
	defer close(errChan)

	go func() {
		err := srv.ListenAndServeTLS(cf, kf)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}
	case <-ctx.Done():
		// Do nothing
	}

	return nil
}

// loadCustomVerifier loads a user provided TUF root.
// Currently only verificatoin options with RFC3161 signed timestamps
// are supported.
func loadCustomVerifier(repo, root, td string) (provider.Verifier, error) {
	var rb []byte
	var v *verifier.Verifier
	var vo = []verify.VerifierOption{
		verify.WithSignedTimestamps(1),
	}
	var err error

	if rb, err = os.ReadFile(root); err != nil {
		return nil, fmt.Errorf("failed to load verifier: %w", err)
	}

	if v, err = verifier.New(rb, repo, td, vo); err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return v, nil
}

// loadVerifiers returns the default verifiers. If pgi is true and tr is
// the empty string, pgi and gh verifiers are returned.
// if the provided trust domain is set, only gh verifier is returend,
// with the set trust domain.
func loadVerifiers(pgi bool, td string) (provider.Verifier, error) {
	var mv = verifier.Multi{
		V: map[string]*verifier.Verifier{},
	}
	var v *verifier.Verifier
	var err error
	var dotcom bool

	// only load PGI if no tenant's trust domain is selected
	if td == "" || td == DotcomTrustDomain {
		dotcom = true
	}

	if pgi && dotcom {
		if v, err = verifier.PGIVerifier(); err != nil {
			return nil, fmt.Errorf("failed to load PGI verifier: %w", err)
		}
		mv.V[verifier.PublicGoodIssuer] = v
		slog.Info("loaded verifier",
			"instance", "public good Sigstore")
	}

	if v, err = verifier.GHVerifier(td); err != nil {
		return nil, fmt.Errorf("failed to load GitHub verifier: %w", err)
	}
	mv.V[verifier.GitHubIssuer] = v
	if td == "" {
		td = "dotcom"
	}
	slog.Info("loaded verifier",
		"instance", "GitHub Sigstore",
		"trust_domain", td)

	return &mv, nil
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
	if r.Response.SystemError == "" {
		// #nosec G706
		slog.Debug("writing response",
			"num_items", len(r.Response.Items))
	} else {
		// #nosec G706
		slog.Error("writing response",
			"system_error", r.Response.SystemError,
			"num_items", len(r.Response.Items))
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(r); err != nil {
		slog.Error("failed writing HTTP response",
			"error", err)
	}
}

func getK8sClient() (*dynamic.DynamicClient, error) {
	if err := v1beta1.AddToScheme(scheme.Scheme); err != nil {
		return nil, err
	}

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	unstructuredClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster kubernetes client: %w", err)
	}

	return unstructuredClient, nil
}
