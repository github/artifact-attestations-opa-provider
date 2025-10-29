package cainjector

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// RunCABundlePatcher periodically updates the caBundle field in the Provider object with the current CA certificates.
func RunCABundlePatcher(ctx context.Context, certsDir *string) error {
	if err := v1beta1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	unstructuredClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("failed to create in-cluster kubernetes client: %w", err)
	}

	for {
		log.Println("Reconciling Provider object...")
		if err := reconcileCABundle(ctx, unstructuredClient, certsDir); err != nil {
			log.Printf("error patching CA bundle in Provider object: %v\n", err)
		}

		time.Sleep(24 * time.Hour)
	}
}

func reconcileCABundle(ctx context.Context, unstructuredClient *dynamic.DynamicClient, certsDir *string) error {
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

	newBundle, err := appendCertificatesToBundle([]byte(provider.Spec.CABundle), caBundle)
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

	log.Println("Successfully updated CA bundle in Provider object.")

	return nil
}
