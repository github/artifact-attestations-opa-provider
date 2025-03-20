FROM alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c as builder

RUN apk add go make

WORKDIR /tmp/aaop

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache make build

FROM alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/aaop/aaop .
COPY --from=builder /tmp/aaop/certs/tls.crt /tmp/aaop/certs/tls.key /certs/

USER 65532:65532

ENTRYPOINT ["/aaop"]
