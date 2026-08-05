FROM ghcr.io/github/gh-base-image/go-builder-noble:20260731-110030-ga8facf72f@sha256:54e0e2bd2fcd8a9a0e0d538a79dfcb3168cd713e93406a9c66232baeabf1efe7 AS builder
WORKDIR /tmp/aaop

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache go build -o aaop cmd/aaop/aaop.go


FROM ghcr.io/github/gh-base-image/gh-base-noble:20260731-094650-g61ba3829f@sha256:965152ebc8311c75bc9db9fc1c178a8c04718ca5d5521c30f55ba40ef229ff4d

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/aaop/aaop .

USER 65532:65532

ENTRYPOINT ["/aaop"]
