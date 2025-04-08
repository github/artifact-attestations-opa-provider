package fixtures

octo_org := {
    "errors": [],
    "responses": [
        [
            "ghcr.io/octoorg/octorepo:latest",
            [
                {
                    "mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
                    "signature": {
                        "certificate": {
                            "certificateIssuer": "CN=Fulcio Intermediate l2,O=GitHub\\, Inc.",
                            "subjectAlternativeName": "https://github.com/octoorg/octorepo/.github/workflows/build.yaml@refs/heads/main",
                            "issuer": "https://token.actions.githubusercontent.com",
                            "githubWorkflowTrigger": "workflow_dispatch",
                            "githubWorkflowSHA": "abc1d720783ae16286faf8ed084c689914abbac3",
                            "githubWorkflowName": "Build image w/ attestation",
                            "githubWorkflowRepository": "octoorg/octorepo",
                            "githubWorkflowRef": "refs/heads/main",
                            "buildSignerURI": "https://github.com/octoorg/octorepo/.github/workflows/build.yaml@refs/heads/main",
                            "buildSignerDigest": "abc1d720783ae16286faf8ed084c689914abbac3",
                            "runnerEnvironment": "github-hosted",
                            "sourceRepositoryURI": "https://github.com/octoorg/octorepo",
                            "sourceRepositoryDigest": "abc1d720783ae16286faf8ed084c689914abbac3",
                            "sourceRepositoryRef": "refs/heads/main",
                            "sourceRepositoryIdentifier": "123525123",
                            "sourceRepositoryOwnerURI": "https://github.com/octoorg",
                            "sourceRepositoryOwnerIdentifier": "98762123",
                            "buildConfigURI": "https://github.com/octoorg/octorepo/.github/workflows/build.yaml@refs/heads/main",
                            "buildConfigDigest": "abc1d720783ae16286faf8ed084c689914abbac3",
                            "buildTrigger": "workflow_dispatch",
                            "runInvocationURI": "https://github.com/octoorg/octorepo/actions/runs/13897293832/attempts/1",
                            "sourceRepositoryVisibilityAtSigning": "private"
                        }
                    },
                    "verifiedTimestamps": [
                        {
                            "type": "TimestampAuthority",
                            "uri": "timestamp.githubapp.com",
                            "timestamp": "2025-03-17T10:36:01Z"
                        }
                    ],
                    "statement": {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [
                            {
                                "name": "ghcr.io/octoorg/octorepo",
                                "digest": {
                                    "sha256": "298558e08dfc4ed37f343d35fcffb8303a2bdf74f4c77a515ce288dee93bcd37"
                                }
                            }
                        ],
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "predicate": {
                            "buildDefinition": {
                                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                "externalParameters": {
                                    "workflow": {
                                        "path": ".github/workflows/build.yaml",
                                        "ref": "refs/heads/main",
                                        "repository": "https://github.com/octoorg/octorepo"
                                    }
                                },
                                "internalParameters": {
                                    "github": {
                                        "event_name": "workflow_dispatch",
                                        "repository_id": "123525123",
                                        "repository_owner_id": "98762123",
                                        "runner_environment": "github-hosted"
                                    }
                                },
                                "resolvedDependencies": [
                                    {
                                        "digest": {
                                            "gitCommit": "abc1d720783ae16286faf8ed084c689914abbac3"
                                        },
                                        "uri": "git+https://github.com/octoorg/octorepo@refs/heads/main"
                                    }
                                ]
                            },
                            "runDetails": {
                                "builder": {
                                    "id": "https://github.com/octoorg/octorepo/.github/workflows/build.yaml@refs/heads/main"
                                },
                                "metadata": {
                                    "invocationId": "https://github.com/octoorg/octorepo/actions/runs/13897293832/attempts/1"
                                }
                            }
                        }
                    }
                }
            ]
        ]
    ],
    "status_code": 200,
    "system_error": ""
}

reusable := {
  "errors": [],
  "responses": [
    [
      "ghcr.io/octoorg/octorepo:reusable",
      [
        {
          "mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
          "signature": {
            "certificate": {
              "buildConfigDigest": "bac1792245301bd84d20bcffa453b4ddf19e4f7b",
              "buildConfigURI": "https://github.com/octoorg/octorepo/.github/workflows/build.yaml@refs/heads/main",
              "buildSignerDigest": "123ba287d1eb31c27b6dd35b57d6c0b79be00a57",
              "buildSignerURI": "https://github.com/buildorg/build-scripts/.github/workflows/image.yml@refs/heads/main",
              "buildTrigger": "workflow_dispatch",
              "certificateIssuer": "CN=Fulcio Intermediate l2,O=GitHub\\, Inc.",
              "githubWorkflowName": "Build image w/ attestation",
              "githubWorkflowRef": "refs/heads/main",
              "githubWorkflowRepository": "octoorg/octorepo",
              "githubWorkflowSHA": "bac1792245301bd84d20bcffa453b4ddf19e4f7b",
              "githubWorkflowTrigger": "workflow_dispatch",
              "issuer": "https://token.actions.githubusercontent.com",
              "runInvocationURI": "https://github.com/octoorg/octorepo/actions/runs/14078191773/attempts/1",
              "runnerEnvironment": "github-hosted",
              "sourceRepositoryDigest": "bac1792245301bd84d20bcffa453b4ddf19e4f7b",
              "sourceRepositoryIdentifier": "123525123",
              "sourceRepositoryOwnerIdentifier": "98762123",
              "sourceRepositoryOwnerURI": "https://github.com/octoorg",
              "sourceRepositoryRef": "refs/heads/main",
              "sourceRepositoryURI": "https://github.com/octoorg/octorepo",
              "sourceRepositoryVisibilityAtSigning": "private",
              "subjectAlternativeName": "https://github.com/buildorg/build-scripts/.github/workflows/image.yml@refs/heads/main"
            }
          },
          "statement": {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
              "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                  "workflow": {
                    "path": ".github/workflows/build.yaml",
                    "ref": "refs/heads/main",
                    "repository": "https://github.com/octoorg/octorepo"
                  }
                },
                "internalParameters": {
                  "github": {
                    "event_name": "workflow_dispatch",
                    "repository_id": "123525123",
                    "repository_owner_id": "98762123",
                    "runner_environment": "github-hosted"
                  }
                },
                "resolvedDependencies": [
                  {
                    "digest": {
                      "gitCommit": "bac1792245301bd84d20bcffa453b4ddf19e4f7b"
                    },
                    "uri": "git+https://github.com/octoorg/octorepo@refs/heads/main"
                  }
                ]
              },
              "runDetails": {
                "builder": {
                  "id": "https://github.com/buildorg/build-scripts/.github/workflows/image.yml@refs/heads/main"
                },
                "metadata": {
                  "invocationId": "https://github.com/octoorg/octorepo/actions/runs/14078191773/attempts/1"
                }
              }
            },
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
              {
                "digest": {
                  "sha256": "2059296ab5f2646f4db0fc14c0ffeb26e9967808ca960d5ce237204ad47d89af"
                },
                "name": "ghcr.io/octoorg/octorepo"
              }
            ]
          },
          "verifiedTimestamps": [
            {
              "timestamp": "2025-03-26T07:58:59Z",
              "type": "TimestampAuthority",
              "uri": "timestamp.githubapp.com"
            }
          ]
        }
      ]
    ]
  ],
  "status_code": 200,
  "system_error": ""
}
