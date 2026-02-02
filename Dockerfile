# v3.21.3
FROM alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS builder

RUN apk update --no-cache && apk add --no-cache go make

WORKDIR /tmp/aaop

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache make build

 # v3.21.3
FROM alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/aaop/aaop .

USER 65532:65532

ENTRYPOINT ["/aaop"]
