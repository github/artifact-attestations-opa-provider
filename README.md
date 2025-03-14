# GitHub Artifact Attestation APA Provider
To integrate [OPA Gatekeeper's new ExternalData
feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata)
with [Artifact attestations](https://github.com/actions/attest) to determine whether
the images are valid by verifying its signatures.

## Limitations

* mTLS between OPA Gatekeeper and the external data provider is not
  yet implemented, only server side TLS
* No custom TUF roots; only PGI Sigstore and GitHub's Sigstore
  instance is supported
* No offline mode; the external data provider requires access to the
  used TUF repositories to be able to update the trust root
* Live refreshes of the trust root, the trust root is downloaded upon
  start and is not refreshed

## Installation


## Verification

## Local installation

1. Create a [kind
   cluster](https://kind.sigs.k8s.io/docs/user/quick-start/).
1. Install Gatekeeper and **enable external data feature**

```
# Add the Gatekeeper Helm repository
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts

# Install the latest version of Gatekeeper with the external data feature enabled.
helm install gatekeeper/gatekeeper \
    --set enableExternalData=true \
    --name-template=gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace
```

1. Generate server TLS for the external data provider

```
$ ./scripts/gen_certs.sh
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

### Cleaning up

```
$ kubectl delete -f validation
$ helm uninstall external-data-provider -n provider-system
```
