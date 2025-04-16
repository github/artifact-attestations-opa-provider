REPOSITORY ?= ghcr.io/github/artifact-attestations-opa-provider
TAG ?= dev
IMG := $(REPOSITORY):$(TAG)

all: aaop

.PHONY: build
build: aaop

.PHONY: aaop
aaop:
	go build -o $@ cmd/aaop/$@.go

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./... -race

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: docker
docker:
	docker build -t ${IMG} .
