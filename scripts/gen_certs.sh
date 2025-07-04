#!/bin/bash

set -u
set -e
set -o pipefail

NAMESPACE=${NAMESPACE:-provider-system}
HOST=${HOST:-artifact-attestations-opa-provider.${NAMESPACE}}

if [ ! -d certs ]; then
   mkdir certs
fi

pushd .
cd certs

#
# Note, only RSA keys appears to be supported
#

# Generate CA cert
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 \
        -subj "/O=GitHub Provider dev/CN=GitHub Provider dev Root CA" \
        -key ca.key \
        -out ca.crt \
        -days 365

# Generate server (provider) key and cert
openssl ecparam -name prime256v1 -genkey -noout -out tls.key
openssl req -new \
        -key tls.key \
        -nodes \
        -subj "/CN=${HOST}" \
        -out server.csr
openssl x509 -req \
        -extfile <(printf "subjectAltName=DNS:%s" "${HOST}") \
        -days 180 \
        -sha256 \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out tls.crt

popd
