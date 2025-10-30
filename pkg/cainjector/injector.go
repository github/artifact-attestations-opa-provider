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

// UpdateCABundle ensures that the `caBundle` field in the Provider object contains the CA certificates in $certsDir/ca.crt.
// If the field is already up to date, no changes are made.
// If an update is made, it sleeps for 10 seconds to allow Gatekeeper to pick up the changes.
// UpdateCABundle removes expired certificates to prevent the bundle from growing indefinitely.
func UpdateCABundle(ctx context.Context, certsDir *string) error {
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

	provider, err := getProvider(ctx, unstructuredClient)
	if err != nil {
		return fmt.Errorf("failed to get Provider object: %w", err)
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

	if err = updateProvider(ctx, provider, newBundle, unstructuredClient); err != nil {
		return fmt.Errorf("failed to update Provider object: %w", err)
	}

	log.Println("Successfully updated CA bundle in Provider object.")
	log.Println("Sleeping for 10s to allow Gatekeeper to pick up the changes...")
	time.Sleep(10 * time.Second)
	log.Println("Done")

	return nil
}

func updateProvider(ctx context.Context, provider *v1beta1.Provider, bundle []byte, client *dynamic.DynamicClient) error {
	provider.Spec.CABundle = string(bundle)

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

func getProvider(ctx context.Context, client *dynamic.DynamicClient) (*v1beta1.Provider, error) {
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
