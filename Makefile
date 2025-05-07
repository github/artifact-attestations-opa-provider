REPOSITORY ?= ghcr.io/github/artifact-attestations-opa-provider
TAG ?= dev
IMG := $(REPOSITORY):$(TAG)
CLUSTER = kind

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
	docker build --platform linux/arm64 -t ${IMG} .

.PHONY: docker-arm
docker-arm:
	docker build --platform linux/arm64 -t ${IMG_ARM} -f Dockerfile.arm .

.PHONY: kind-load-image-arm
kind-load-image:
	kind load docker-image ${IMG} --name ${CLUSTER}

.PHONY: test-rego
test-rego:
	cd rego && opa test . -v

.PHONY: integration-test
integration-test:
	HOST=localhost ./scripts/gen_certs.sh
	./scripts/integration_test.sh
