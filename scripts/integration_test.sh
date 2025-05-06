#!/bin/bash

set -e
set -u
set -o pipefail

RES=0
# Example request to the OPA provider
BODY=`cat <<EOF
{
    "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
    "kind": "ProviderRequest",
    "request": {
        "keys": ["ghcr.io/github/artifact-attestations-opa-provider:unsigned"]
    }
}
EOF
`

./aaop -certs certs&
sleep 5

# Post request to the OPA provider
curl -X POST \
    -H "Content-Type: application/json" \
    --cacert certs/ca.crt \
    --insecure \
    -d "$BODY" \
    https://localhost:8080/

sleep 1
COUNT=`curl -s http://localhost:9090/metrics | grep ^aaop_attestations_retrieved_fail | sed 's/aaop_attestations_retrieved_fail //g' | sed 's/\n//g'`
if [ ! "$COUNT" -gt 0 ]; then
    echo "retrieve metrics not increased"
    RES=1
fi

kill $(jobs -p)
exit ${RES}
