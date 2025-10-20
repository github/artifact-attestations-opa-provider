package cainjector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

var (
	// ErrNoPEMData is returned when the given data contained no PEM
	ErrNoPEMData = errors.New("no PEM data was found in given input")
)

func RunCABundlePatcher(ctx context.Context, certsDir *string) error {
	v1beta1.AddToScheme(scheme.Scheme)
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	unstructuredClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("failed to create in-cluster kubernetes client: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("failed to create in-cluster kubernetes clientset: %w", err)
	}

	for {
		log.Println("Reconciling Provider object...")
		if err := reconcileCABundle(ctx, unstructuredClient, k8sClient, certsDir); err != nil {
			log.Printf("error patching CA bundle in Provider object: %v", err)
		}

		time.Sleep(6 * time.Hour)
	}
}

func reconcileCABundle(ctx context.Context, unstructuredClient *dynamic.DynamicClient, k8sClient *kubernetes.Clientset, certsDir *string) error {
	rawProvider, err := unstructuredClient.Resource(schema.GroupVersionResource{
		Group:    "externaldata.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "providers",
	}).Get(ctx, "artifact-attestations-opa-provider", v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get Provider object: %w", err)
	}

	var provider v1beta1.Provider
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(rawProvider.UnstructuredContent(), &provider)
	if err != nil {
		return fmt.Errorf("failed to convert Provider object: %w", err)
	}

	caBundle, err := os.ReadFile(path.Join(*certsDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	newBundle, err := AppendCertificatesToBundle([]byte(provider.Spec.CABundle), caBundle)
	if err != nil {
		return fmt.Errorf("failed to append CA certificates to bundle: %w", err)
	}

	if provider.Spec.CABundle == string(newBundle) {
		log.Println("CA bundle is already up to date, no changes made.")
		return nil
	}

	provider.Spec.CABundle = string(newBundle)

	updatedUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&provider)
	if err != nil {
		return fmt.Errorf("failed to convert updated Provider object: %w", err)
	}

	_, err = unstructuredClient.Resource(schema.GroupVersionResource{
		Group:    "externaldata.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "providers",
	}).Update(ctx, &unstructured.Unstructured{Object: updatedUnstructured}, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update Provider object: %w", err)
	}

	return nil
}

func decodeMultipleCerts(certBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		var err error

		// decode the tls certificate pem
		block, certBytes, err = safeDecodeInternal(certBytes)
		if err != nil {
			if err == ErrNoPEMData {
				break
			}

			return nil, err
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing X.509 certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("error decoding certificate PEM block: no valid certificates found")
	}

	return certs, nil
}
