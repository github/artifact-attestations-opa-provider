package authn

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
)

// KeyChainProvider is used to provide k8s keychains, which can be used
// to authenticate certain requests like fetching resources from an OCI
// registry.
type KeyChainProvider struct {
	namespace        string
	imagePullSecrets []string
}

// NewKeyChainProvider returns a new instance for a namespace and a set of
// image pull secrets. If namesapce is not set, or no image pull secret
// references are provided, the default keychain is will be used for further
// requests to get a key chain.
func NewKeyChainProvider(ns string, ips []string) *KeyChainProvider {
	fmt.Printf("configure authn with image pull secrets %+v for namespace %s\n",
		ips, ns)

	return &KeyChainProvider{
		namespace:        ns,
		imagePullSecrets: ips,
	}
}

func (k *KeyChainProvider) KeyChain(ctx context.Context) (authn.Keychain, error) {
	var kc authn.Keychain
	var kcs = []authn.Keychain{
		authn.DefaultKeychain,
	}
	var err error

	// Add the kubenertes authenticator
	kc, err = kubernetes.NewInCluster(ctx, kubernetes.Options{
		Namespace:        k.namespace,
		ImagePullSecrets: k.imagePullSecrets,
	})
	if err != nil {
		fmt.Printf("can't add kubernetes key chain: %s\n", err)
	} else {
		kcs = append(kcs, kc)
	}

	// Add a "cloud k8s" authenticator
	kc, err = k8schain.NewInCluster(ctx, k8schain.Options{
		Namespace: k.namespace,
	})
	if err != nil {
		fmt.Printf("can't add k8schain key chain: %s\n", err)
	} else {
		kcs = append(kcs, kc)
	}

	return authn.NewMultiKeychain(kcs...), nil
}
