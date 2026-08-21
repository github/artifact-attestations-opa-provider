FROM golang:1.27rc3-alpine3.23@sha256:f561f8ea7bf9b015cda685bdc9ce3904c592af92e6d1f90c3c953f3c8019d2ca AS builder

WORKDIR /tmp/aaop

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache go build -o aaop cmd/aaop/aaop.go

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/aaop/aaop .

USER 65532:65532

ENTRYPOINT ["/aaop"]
