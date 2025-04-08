package policies_test

import data.policies
import data.fixtures

# From org should pass if at least one correct org is provided
test_from_org_pass if {
    policies.fromOrg(fixtures.octo_org, ["unkown", "octoorg"])
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

# From repo should pass if at least one repo is valid
test_from_repo_pass if {
    policies.fromRepo(fixtures.octo_org, ["unkown/unkown", "octoorg/octorepo"])
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

# Same repo and signer
test_with_signer_pass if {
    policies.fromOrgAndSignerRepo(fixtures.octo_org, ["unknown", "octoorg"], ["unkown/octorepo", "octoorg/octorepo"])
}

# With a signer from a different org
test_with_signer_pass if {
    policies.fromOrgAndSignerRepo(fixtures.reusable, ["unknown", "octoorg"], ["octoorg/octorepo", "buildorg/build-scripts"])
}

# Empty input
test_with_signer_empty if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, [], [])
}

test_with_signer_empty if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, [""], [])
}

test_with_signer_empty if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, [], [""])
}

test_with_signer_empty if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, [""], [""])
}

# Verify that no prefix weakness exists for the orgs
test_from_repo_invalid if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, ["unkown", "ctoorg", "octoor", "aoctoorg", "octoorga"], ["octoorg/octorepo"])
}

# Verify that no prefix weakness exists for the signer repos
test_from_repo_invalid if {
    not policies.fromOrgAndSignerRepo(fixtures.octo_org, ["octoorg"], ["ctoorg/octorepo", "octoorg/octorep", "octoor/octorepo", "octoorg/ctorepo"])
}
