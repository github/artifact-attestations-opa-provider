REPOSITORY ?= openpolicyagent/gatekeeper-external-data-provider
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
	docker buildx build --platform linux/amd64 --load -t ${IMG} .

.PHONY: kind-load-image
kind-load-image:
	kind load docker-image ${IMG} --name ${CLUSTER}
