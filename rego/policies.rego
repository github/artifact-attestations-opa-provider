package policies

fromOrg (resp, orgs) if {
   some i, j, k, l
   orgUri := resp.responses[i][j][k].signature.certificate.sourceRepositoryOwnerURI
   endswith(orgUri, concat("", ["/", orgs[l]]))
}

fromRepo (resp, repos) if {
   some i
   uri := resp.responses[_][_][_].signature.certificate.sourceRepositoryURI
   endswith(uri, concat("", ["/", repos[i]]))
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
