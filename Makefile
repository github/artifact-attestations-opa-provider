REPOSITORY ?= ghcr.io/github/artifact-attestations-opa-provider
TAG ?= dev
IMG := $(REPOSITORY):$(TAG)
CLUSTER = kind

all: aaop

.PHONY: build
build: aaop ## Build binary

.PHONY: aaop
aaop:
	go build -o $@ cmd/aaop/$@.go

.PHONY: tidy
tidy: ## Run go mod tidy
	go mod tidy

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: test
test: ## Run unit tests
	go test ./... -race

.PHONY: fmt
fmt: ## Run go fmt
	go fmt ./...

.PHONY: docker
docker: ## Build image
	docker build --platform linux/arm64 -t ${IMG} .

.PHONY: kind-load-image-arm
kind-load-image: ## Load image with Kind
	kind load docker-image ${IMG} --name ${CLUSTER}

.PHONY: test-rego
test-rego: ## Run rego tests
	cd rego && opa test . -v

.PHONY: integration-test
integration-test: ## Run integration tests
	HOST=localhost ./scripts/gen_certs.sh
	./scripts/integration_test.sh

.PHONY: coverage ## Go coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_0-9.\/-]+:.*?##/ { printf "  %-30s %s\n", $$1, $$2 } /^##@/ { printf "\n%s\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
