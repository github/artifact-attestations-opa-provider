package policies

fromOrg (resp, orgs) if {
   some i, j, k, l
   orgUri := resp.responses[i][j][k].signature.certificate.sourceRepositoryOwnerURI
   # Prefix the org name with / before doing comparisson
   endswith(orgUri, concat("", ["/", orgs[l]]))
}

fromRepo (resp, repos) if {
   some i, j, k, l
   uri := resp.responses[i][j][k].signature.certificate.sourceRepositoryURI
   # Prefix the repo name with / before doing comparisson
   endswith(uri, concat("", ["/", repos[l]]))
}

fromOrgAndSignerRepo(resp, orgs, signerRepos) if {
   some i, j, k, l, m
   orgUri := resp.responses[i][j][k].signature.certificate.sourceRepositoryOwnerURI
   signerUri := resp.responses[i][j][k].signature.certificate.buildSignerURI
   # Verify source owner org is allowed
   endswith(orgUri, concat("", ["/", orgs[l]]))
   # Verify signer org is allowed
   # Remove the path to the repo, workflow and ref
   # find the occurence of `/.github/` and trim everything after it
   p := indexof(signerUri, "/.github/")
   signerRepoTrim := substring(signerUri, 0, p)
   # add back the / prefix to get proper delimiter when doing comparisson
   signerRepo := concat("", ["/", signerRepoTrim])
   endswith(signerRepo, concat("", ["/", signerRepos[m]]))
}
