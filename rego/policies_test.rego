package policies_test

import data.policies
import data.fixtures

# From org should pass if at least one correct org is provided
test_from_org_pass if {
    policies.fromOrg(fixtures.octo_org, ["unkown", "octoorg"])
}

# Should fail when issuer is not matching
test_from_org_issuer if {
    not policies.fromOrg(fixtures.custom_issuer, ["unkown", "octoorg"])
}

# Empty org should fail
test_from_org_empty if {
    not policies.fromOrg(fixtures.octo_org, [""])
}

test_from_org_empty if {
    not policies.fromOrg(fixtures.octo_org, [])
}

# Verify that no prefix weakness exists
test_from_org_invalid if {
    not policies.fromOrg(fixtures.octo_org, ["unkown", "octoorga", "ctoorg", "aoctoorg"])
}

test_from_org_non_provenance if {
    not policies.fromOrg(fixtures.non_provenance, ["octoorg"])
}

# From repo should pass if at least one repo is valid
test_from_repo_pass if {
    policies.fromRepo(fixtures.octo_org, ["unkown/unkown", "octoorg/octorepo"])
}

# Should fail when issuer is not matching
test_from_repo_issuer if {
    not policies.fromRepo(fixtures.custom_issuer, ["unkown/unkown", "octoorg/octorepo"])
}

# Empty repo shoud fail
test_from_repo_empty if {
    not policies.fromRepo(fixtures.octo_org, [""])
}

test_from_repo_empty if {
    not policies.fromRepo(fixtures.octo_org, [])
}

# Verify that no prefix weakness exists
test_from_repo_invalid if {
    not policies.fromRepo(fixtures.octo_org, ["unkown/unkown", "ctoorg/octorepo", "aoctoorg/octorepo", "octoorga/octorepo", "octoorg/aoctorepo", "octoorg/octorep", "octoorg/octorepoa"])
}

test_from_repo_non_provenance if {
    not policies.fromRepo(fixtures.non_provenance, ["octoorg/octorepo"])
}

# Same repo and signer
test_with_signer_pass if {
    policies.fromOrgWithSignerRepo(fixtures.octo_org, ["unknown", "octoorg"], ["unkown/octorepo", "octoorg/octorepo"])
}

# With a signer from a different org
test_with_signer_pass if {
    policies.fromOrgWithSignerRepo(fixtures.reusable, ["unknown", "octoorg"], ["octoorg/octorepo", "buildorg/build-scripts"])
}

# Should fail when issuer is not matching
test_with_signer_issuer if {
    not policies.fromOrgWithSignerRepo(fixtures.custom_issuer, ["unknown", "octoorg"], ["octoorg/octorepo", "buildorg/build-scripts"])
}

# Empty input
test_with_signer_empty if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, [], [])
}

test_with_signer_empty if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, [""], [])
}

test_with_signer_empty if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, [], [""])
}

test_with_signer_empty if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, [""], [""])
}

# Verify that no prefix weakness exists for the orgs
test_with_signer_invalid if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, ["unkown", "ctoorg", "octoor", "aoctoorg", "octoorga"], ["octoorg/octorepo"])
}

# Verify that no prefix weakness exists for the signer repos
test_with_signer_invalid if {
    not policies.fromOrgWithSignerRepo(fixtures.reusable, ["octoorg"], ["ctoorg/octorepo", "octoorg/octorep", "octoor/octorepo", "octoorg/ctorepo"])
}

# Make sure that a JSON doc matching the provenance does not pass
# if the predicate type is differing
test_with_signer_non_provenance if {
    not policies.fromOrgWithSignerRepo(fixtures.non_provenance, ["octoorg"], ["buildorg/build-scripts"])
}

# If multiple attestations are returned, the verification should still pass
test_multiple_attestations if {
    policies.fromOrgWithSignerRepo(fixtures.multiple, ["octoorg"], ["octoorg/octorepo"])
}

# Custom attestations should also work
test_custom_attestation if {
    policies.customAttestation(fixtures.multiple, "value1")
}
