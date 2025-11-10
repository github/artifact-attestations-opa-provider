#!/bin/bash

set -e
set -u
set -o pipefail

metrics_failed() {
    curl -s http://localhost:9090/metrics | grep ^aaop_attestations_retrieved_fail | sed 's/aaop_attestations_retrieved_fail //g' | tr -d '\n'
}

metrics_no_attestation() {
    curl -s http://localhost:9090/metrics | grep ^aaop_attestations_missing_total | sed 's/aaop_attestations_missing_total //g' | tr -d '\n'
}

metrics_ok() {
    curl -s http://localhost:9090/metrics | grep ^aaop_attestations_verified_ok | sed 's/aaop_attestations_verified_ok //g' | tr -d '\n'
}

validate() {
    body=$1
    curl -X POST \
        -s \
        -H "Content-Type: application/json" \
        --cacert certs/ca.crt \
        -d "${body}" \
        https://localhost:8080
}

cleanup() {
    kill $(jobs -p) 2>/dev/null || true
}

RES=0
INVALID_IMAGE="ghcr.io/github/artifact-attestations-opa-provider:notfound"
INVALID_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["${INVALID_IMAGE}"]
    }
}
EOF
`

UNSIGNED_IMAGE="ghcr.io/github/artifact-attestations-opa-provider:unsigned"
UNSIGNED_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["${UNSIGNED_IMAGE}"]
    }
}
EOF
`

SIGNED_IMAGE="ghcr.io/github/artifact-attestations-opa-provider:dev"
SIGNED_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["${SIGNED_IMAGE}"]
    }
}
EOF
`

BROKEN_IMAGE="foo+bar"
MULTIPLE_IMG_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": [
            "${SIGNED_IMAGE}",
            "${UNSIGNED_IMAGE}",
            "${BROKEN_IMAGE}"
        ]
    }
}
EOF
`

trap cleanup INT EXIT TERM

./aaop -certs certs&
sleep 5

# Perform a request with an image that does not exist
echo Verifying invalid image ref
validate "${INVALID_BODY}"
sleep 1

COUNT=`metrics_failed`
if [ ! "${COUNT}" -gt 0 ]; then
    echo "ERROR: failed retrieval metrics counter did not increase"
    RES=1
fi

COUNT=`metrics_ok`
if [ ! "${COUNT}" -eq 0 ]; then
    echo "ERROR: found verified attestations"
    RES=1
fi


COUNT=`metrics_no_attestation`
if [ ! "${COUNT}" -eq 0 ]; then
    echo "ERROR: no attesations metric increased"
    RES=1
fi

# Perform a request with the unsigned image
echo Verifying an unsigned image
validate "${UNSIGNED_BODY}"
sleep 1

COUNT=`metrics_no_attestation`
if [ ! "${COUNT}" -gt 0 ]; then
    echo "ERROR: failed no attestation counter did not increase"
    RES=1
fi

COUNT=`metrics_ok`
if [ ! "${COUNT}" -eq 0 ]; then
    echo "ERROR: found verified attestations"
    RES=1
fi

# Perform a request with a signed image
echo Verifying a signed image
KEY=`validate "${SIGNED_BODY}" | jq -r '.response.items[0].key'`
sleep 1

COUNT=`metrics_ok`
if [ ! "${COUNT}" -gt 0 ]; then
    echo "ERROR: verification was not successful for image ${SIGNED_IMAGE}"
    RES=1
fi

# Verify that the key in the response contains the expected image/tag
if [ "${SIGNED_IMAGE}" != "${KEY}" ]; then
    echo "ERROR: unexpected image ${KEY} in response for image ${SIGNED_IMAGE}"
    RES=1
fi

# Perform a request with multiple images
echo Verify with multiple images
output=`validate "${MULTIPLE_IMG_BODY}" | jq -r '.response.items[].error'`
# There should be one error: unsigned, one invalid reference and one null
echo "$output" | grep -q "^null$" && \
echo "$output" | grep -q "image_unsigned" && \
echo "$output" | grep -q "invalid_reference" && \
echo "Validate multiple image successful" || RES=1

if [ ! ${RES} -eq 0 ]; then
   echo "Integration test failed"
fi

exit ${RES}
