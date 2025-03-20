REPOSITORY ?= github/artifact-attestations-opa-provider
IMG := $(REPOSITORY):dev
CLUSTER = kind # or gatekeeper

all: aaop

.PHONY: build
build: aaop

.PHONY: aaop
aaop:
	go build -o $@ cmd/aaop/$@.go

tidy:
	go mod tidy

lint:
	golangci-lint run

test:
	go test ./... -race

snapshot:
	goreleaser release --clean --snapshot --skip-sign --skip-publish

release:
	goreleaser release --clean

fmt:
	go fmt ./...

.PHONY: cver
cver:
	go build -o $@ cmd/cver/$@.go

.PHONY: docker
docker:
	docker build --platform linux/arm64 -t ${IMG} .

.PHONY: docker-arm
docker-arm:
	docker build --platform linux/arm64 -t ${IMG_ARM} -f Dockerfile.arm .

.PHONY: kind-load-image-arm
kind-load-image:
	kind load docker-image ${IMG} --name ${CLUSTER}
