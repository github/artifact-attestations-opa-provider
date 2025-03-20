package authn

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/kubernetes"
)

type KeyChainProvider struct {
	serviceName      string
	namespace        string
	imagePullSecrets []string
}

func NewKeyChainProvider(ns string, ips []string) *KeyChainProvider {
	fmt.Printf("configure authn with image pull secrets %+v for namespace %s\n",
		ips, ns)

	return &KeyChainProvider{
		namespace:        ns,
		imagePullSecrets: ips,
	}
}

func (k *KeyChainProvider) KeyChain(ctx context.Context) (authn.Keychain, error) {
	if k.namespace == "" || len(k.imagePullSecrets) == 0 {
		return authn.DefaultKeychain, nil
	}

	var opt = kubernetes.Options{
		Namespace:        k.namespace,
		ImagePullSecrets: k.imagePullSecrets,
	}

	return kubernetes.NewInCluster(ctx, opt)
}
