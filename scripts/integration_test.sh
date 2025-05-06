#!/bin/bash

set -e
set -u
set -o pipefail

metrics_failed() {
    curl -s http://localhost:9090/metrics | grep ^aaop_attestations_retrieved_fail | sed 's/aaop_attestations_retrieved_fail //g' | tr -d '\n'
}

metrics_ok() {
    curl -s http://localhost:9090/metrics | grep ^aaop_attestations_verified_ok | sed 's/aaop_attestations_verified_ok //g' | tr -d '\n'
}

RES=0
# Example request to the OPA provider
UNSIGNED_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["ghcr.io/github/artifact-attestations-opa-provider:unsigned"]
    }
}
EOF
`

SIGNED_BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["ghcr.io/tinaheidinger/test-container:latest"]
    }
}
EOF
`

./aaop -certs certs&
sleep 5

# Perform a request with the unsigned image
echo Verifying an unsigned image
curl -X POST \
    -H "Content-Type: application/json" \
    --insecure \
    -d "${UNSIGNED_BODY}" \
    https://localhost:8080/
sleep 1

COUNT=`metrics_failed`
if [ ! "${COUNT}" -gt 0 ]; then
    echo "retrieve metrics not increased"
    RES=1
fi

COUNT=`metrics_ok`
if [ ! "${COUNT}" -eq 0 ]; then
    echo "found verified attestations"
    RES=1
fi

# Perform a request with a signed image
echo Verifying a signed image
curl -X POST \
    -H "Content-Type: application/json" \
    --cacert certs/ca.crt \
    --insecure \
    -d "${SIGNED_BODY}" \
    https://localhost:8080/
sleep 1

COUNT=`metrics_ok`
if [ ! "${COUNT}" -gt 0 ]; then
    echo "verification was not successful"
    RES=1
fi

kill $(jobs -p)
exit ${RES}
