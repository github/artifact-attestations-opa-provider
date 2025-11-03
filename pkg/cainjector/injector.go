package cainjector

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var propagationDelay = 10 * time.Second

// UpdateCABundle ensures that the `caBundle` field in the Provider object contains the CA certificates in $certsDir/ca.crt.
// If the field is already up to date, no changes are made.
// If an update is made, it sleeps for 10 seconds to allow Gatekeeper to pick up the changes.
// UpdateCABundle removes expired certificates to prevent the bundle from growing indefinitely.
func UpdateCABundle(ctx context.Context, k8sClient dynamic.Interface, bundlePath string) error {
	provider, err := getProvider(ctx, k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get Provider object: %w", err)
	}

	caBundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	newBundle, err := mergeAndEncode(provider.Spec.CABundle, caBundle)
	if err != nil {
		return fmt.Errorf("failed to append CA certificates to bundle: %w", err)
	}

	if provider.Spec.CABundle == newBundle {
		log.Println("CA bundle is already up to date, no changes made.")
		return nil
	}

	if err = updateProvider(ctx, k8sClient, provider, newBundle); err != nil {
		return fmt.Errorf("failed to update Provider object: %w", err)
	}

	log.Println("Successfully updated CA bundle in Provider object.")
	log.Println("Sleeping for 10s to allow Gatekeeper to pick up the changes...")
	time.Sleep(propagationDelay)
	log.Println("Done")

	return nil
}

// mergeAndEncode an additional PEM-encoded cert bundle with an base64 andPEM-encoded certificate bundle,
// It also removes duplicates and expired certificates.
func mergeAndEncode(encodedBundle string, additional []byte) (string, error) {
	bundle0, err := base64.StdEncoding.DecodeString(encodedBundle)
	if err != nil {
		return "", fmt.Errorf("failed to decode existing CA bundle: %w", err)
	}

	certs0, err := parseCertificates(bundle0)
	if err != nil {
		return "", fmt.Errorf("failed to parse first certificate bundle: %w", err)
	}

	certs1, err := parseCertificates(additional)
	if err != nil {
		return "", fmt.Errorf("failed to parse second certificate bundle: %w", err)
	}

	// Merge certificates and track unique ones by their DER encoding
	uniqueCerts := make(map[string]bool)
	now := time.Now()
	buffer := bytes.NewBuffer([]byte{})

	for _, cert := range append(certs0, certs1...) {
		// Skip expired certificates
		if cert.NotAfter.Before(now) {
			log.Printf("Ignoring expired certificate: CN=%s, NotAfter=%s", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339))
			continue
		}

		// Use the DER encoding as a unique key to deduplicate
		key := string(cert.Raw)
		if _, exists := uniqueCerts[key]; !exists {
			uniqueCerts[key] = true

			if err = pem.Encode(buffer, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}); err != nil {
				return "", fmt.Errorf("failed to encode certificate to PEM: %w", err)
			}
		}
	}

	if buffer.Len() == 0 {
		return "", errors.New("resulting CA bundle is empty after removing expired certificates")
	}

	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func parseCertificates(bundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(bundle) > 0 {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func updateProvider(ctx context.Context, client dynamic.Interface, provider *v1beta1.Provider, bundle string) error {
	provider.Spec.CABundle = bundle

	updatedUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(provider)
	if err != nil {
		return fmt.Errorf("failed to convert updated Provider object: %w", err)
	}

	_, err = client.Resource(schema.GroupVersionResource{
		Group:    "externaldata.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "providers",
	}).Update(ctx, &unstructured.Unstructured{Object: updatedUnstructured}, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update Provider object: %w", err)
	}

	return nil
}

func getProvider(ctx context.Context, client dynamic.Interface) (*v1beta1.Provider, error) {
	rawProvider, err := client.Resource(schema.GroupVersionResource{
		Group:    "externaldata.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "providers",
	}).Get(ctx, "artifact-attestations-opa-provider", v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Provider object: %w", err)
	}

	var provider v1beta1.Provider
	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(rawProvider.UnstructuredContent(), &provider); err != nil {
		return nil, fmt.Errorf("failed to convert Provider object: %w", err)
	}

	return &provider, nil
}
