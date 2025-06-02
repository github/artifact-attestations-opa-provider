# v3.21.3
FROM alpine@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715 as builder

RUN apk update --no-cache && apk add --no-cache go make

WORKDIR /tmp/aaop

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache make build

 # v3.21.3
FROM alpine@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/aaop/aaop .

USER 65532:65532

ENTRYPOINT ["/aaop"]
