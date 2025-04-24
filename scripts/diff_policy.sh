#!/bin/bash

set -ue -o pipefail

# The policy definitions differs slightly from within the constraint
# tempalte, and the rego definitions used during testing.
# Extract the policies from both definitions, strip newlines and white
# spaces, then compare them to detect drift.

diffp() {
    file=$1
    func=$2

    # The regex to match the function definition contains three preceding
    # whitespaces to not match the location where it's called.
    got=`perl -0777 -ne "print \\$1 if /(   ${func}.*?})/s" validation/${file} \
         | perl -ne '$. > 1 && print'| tr -d ' \n'`
    want=`perl -0777 -ne "print \\$1 if /(${func}.*?})/s" rego/policies.rego \
        | perl -ne '$. > 1 && print' | tr -d ' \n'`

    if [ "${got}" != "${want}" ]; then
        echo "policy ${func} differs in constraint template ${file}"
        echo ${got}
        echo vs
        echo ${want}
       exit 1
    fi
}

diffp from-org-constraint-template.yaml fromOrg
diffp from-org-with-signer-constraint-template.yaml fromOrgWithSigner
diffp from-repo-constraint-template.yaml fromRepo

echo "No differences detected"
