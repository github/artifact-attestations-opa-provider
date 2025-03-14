#!/bin/bash

set -u
set -e
set -o pipefail

NAMESPACE=${NAMESPACE:-provider-system}

if [ ! -d certs ]; then
   mkdir certs
fi

pushd .
cd certs

#
# Note, only RSA keys appears to be supported
#

# Generate CA cert
# openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl genrsa -out ca.key 2048
openssl req -new -x509 \
        -subj "/O=GitHub Provider dev/CN=GitHub Provider dev Root CA" \
        -key ca.key \
        -out ca.crt \
        -days 365

# Generate server (provider) key and cert
# openssl ecparam -name prime256v1 -genkey -noout -out tls.key
openssl genrsa -out tls.key 2048
openssl req -new \
        -key tls.key \
        -nodes \
        -subj "/CN=artifact-attestations-opa-provider.${NAMESPACE}" \
        -out server.csr
openssl x509 -req \
        -extfile <(printf "subjectAltName=DNS:artifact-attestations-opa-provider.%s" "${NAMESPACE}") \
        -days 180 \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out tls.crt

popd
