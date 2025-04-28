# RSA demo instructions for local computer use

## 1. Prepare environment

1. Create a [kind
   cluster](https://kind.sigs.k8s.io/docs/user/quick-start/):

```
$ brew install kind
$ kind create cluster
```

2. Install Gatekeeper

```
$ helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
$ helm install gatekeeper/gatekeeper \
    --set enableExternalData=true \
    --name-template=gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace
```

3. Generate server TLS for the probider

```
$ ./scripts/gen_certs.sh
```

4. Build and load the docker image

```
$ make docker
$ make kind-load-image
```

5. Install the Artifacts attestation OPA data provider

```
$ helm install artifact-attestations-opa-provider charts/artifact-attestations-opa-provider \
    --set provider.tls.caBundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --set serverCert="$(cat certs/tls.crt | base64 | tr -d '\n\r')" \
    --set serverKey="$(cat certs/tls.key | base64 | tr -d '\n\r')" \
    --namespace provider-system \
    --create-namespace
```

6. Install the constraint template

This step will make sure that only docker images built from the `kommendorkapten`
GitHub Organization is admitted to the cluster.

If you would like to change this to your org, a good start is to fork
[this repo](https://github.com/kommendorkapten/rsademo) and build the
image, it's just a plain `nginx` image.

```
$ kubectl apply -f validation/rsa-demo-constraint-template.yaml
$ kubectl apply -f validation/rsa-demo-constraint.yaml
```

For showing other default policies we will ship, see the other files
in the [validation](validation/) repo:

* [from-org-constraint-template.yaml](validation/from-org-constraint-template.yaml)
* [from-org-with-signer-constraint-template.yaml](validation/from-org-with-signer-constraint-template.yaml)
* [from-repo-constraint-template.yaml](validation/from-repo-constraint-template.yaml)
* [rsa-demo-constraint-template.yaml](validation/rsa-demo-constraint-template.yaml)

> [!NOTE]
> For all rego examples, the org and repo names are just placeholders
> for the users' real org/repo names.

7. Deploy without attestation (will fail)

```
$ kubectl apply -f rsa-demo-deployment-no-attestation.yaml
```

Verify that the deployment is not creating any pods:

```
$ kubectl describe deployment nginx-no-att
```

8. Deploy with attestation (will pass)

```
$ kubectl apply -f rsa-demo-deployment-attestation.yaml
```

Verify that the deployment creates pods

```
$ kubectl describe deployment nginx-att
```

## Clean up

```
$ kubectl delete -f validation
$ helm uninstall artifact-attestations-opa-provider -n provider-system
```
