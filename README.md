# GitHub Artifact Attestations OPA Provider
To integrate [OPA Gatekeeper's new ExternalData
feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata)
with [Artifact attestations](https://github.com/actions/attest) to determine whether
the images are valid by verifying its signatures.

## Limitations

* mTLS between OPA Gatekeeper and the external data provider is not
  yet implemented, only server side TLS
* Fix up Helm templates

## Installation


## Verification

## Local installation

1. Create a [kind
   cluster](https://kind.sigs.k8s.io/docs/user/quick-start/).
1. Prepare `pull-secret` for private OCI registry (Optional)

```
$ kubectl create secret docker-registry \
          ghcr-login-secret \
          --docker-server=https://ghcr.io \
          --docker-username=$YOUR_GITHUB_USERNAME \
          --docker-password=$YOUR_GITHUB_TOKEN \
          --docker-email=$YOUR_EMAIL
```

1. Prepare a pull secret for the OPA external data provider (Optional)

```
$ kubectl create secret \
          -n provider-system \
          docker-registry aa-ghcr-login-secret \
          --docker-server=https://ghcr.io \
          --docker-username=$YOUR_GITHUB_USERNAME \
          --docker-password=$YOUR_GITHUB_TOKEN \
          --docker-email=$YOUR_EMAIL
```

1. Install Gatekeeper and **enable external data feature**

```
# Add the Gatekeeper Helm repository
$ helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts

# Install the latest version of Gatekeeper with the external data feature enabled.
$ helm install gatekeeper/gatekeeper \
    --set enableExternalData=true \
    --name-template=gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace
```

1. Generate server TLS for the external data provider and load them
   into secrets

```
$ ./scripts/gen_certs.sh
```

```
$ cat cert-secrets.yaml

apiVersion: v1
kind: Secret
metadata:
  name: provider-tls-cert
  namespace: provider-system
data:
  tls.crt: B64 of file tls.crt
  tls.key: B64 of file tls.key
$ kubectl apply -f cert-secrets.yaml
```

1. Build and load the docker image

```
$ make docker
$ make kind-load-image
```

1. Install the data provider

```
$ helm install artifact-attestations-opa-provider charts/artifact-attestations-opa-provider \
    --set clientCAFile="" \
    --set provider.tls.caBundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --namespace provider-system \
    --create-namespace
```

1. Install constraint template and constraint.

```
$ kubectl apply -f validation/artifact-attestations-constraint-template.yaml
$ kubectl apply -f validation/artifact-attestations-constraint.yaml
```

1. Test with an image from wrong repository.

```
$ kubectl run nginx --image=ghcr.io/tinaheidinger/test-container:latest  --dry-run=server -ojson
```

1. Correctly signed

```
$ kubectl run nginx --image=ghcr.io/kommendorkapten/ghademo:latest --dry-run=server -ojson
```

### Cleaning up

```
$ kubectl delete -f validation
$ helm uninstall artifact-attestations-opa-provider -n provider-system
```
