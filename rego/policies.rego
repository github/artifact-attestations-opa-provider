package policies

fromOrg (resp, orgs) if {
   some i, j, k, l
   provenance := "https://slsa.dev/provenance/v1"
   issuer := "https://token.actions.githubusercontent.com"

   provenance == resp.responses[i][j][k].statement.predicateType
   issuer == resp.responses[i][j][k].signature.certificate.issuer
   orgUri := resp.responses[i][j][k].signature.certificate.sourceRepositoryOwnerURI
   # Prefix the org name with / before doing comparison
   endswith(orgUri, concat("", ["/", orgs[l]]))
}

fromRepo (resp, repos) if {
   some i, j, k, l
   provenance := "https://slsa.dev/provenance/v1"
   issuer := "https://token.actions.githubusercontent.com"

   provenance == resp.responses[i][j][k].statement.predicateType
   issuer == resp.responses[i][j][k].signature.certificate.issuer
   uri := resp.responses[i][j][k].signature.certificate.sourceRepositoryURI
   # Prefix the repo name with / before doing comparison
   endswith(uri, concat("", ["/", repos[l]]))
}

fromOrgWithSignerRepo(resp, orgs, signerRepos) if {
   some i, j, k, l, m
   provenance := "https://slsa.dev/provenance/v1"
   issuer := "https://token.actions.githubusercontent.com"

   provenance == resp.responses[i][j][k].statement.predicateType
   issuer == resp.responses[i][j][k].signature.certificate.issuer
   orgUri := resp.responses[i][j][k].signature.certificate.sourceRepositoryOwnerURI
   signerUri := resp.responses[i][j][k].signature.certificate.buildSignerURI
   # Verify source owner org is allowed
   endswith(orgUri, concat("", ["/", orgs[l]]))
   # Verify signer org is allowed
   # Remove the path to the repo, workflow and ref
   # find the occurence of `/.github/` and trim everything after it
   p := indexof(signerUri, "/.github/")
   signerRepoTrim := substring(signerUri, 0, p)
   # add back the / prefix to get proper delimiter when doing comparison
   signerRepo := concat("", ["/", signerRepoTrim])
   endswith(signerRepo, concat("", ["/", signerRepos[m]]))
}

# This is an example showing how custom attestations can be verified
customAttestation(resp, val) if {
   some i, j, k
   custom := "https://example.com/custom/v1"

   custom == resp.responses[i][j][k].statement.predicateType
   val == resp.responses[i][j][k].statement.predicate.key1
}
