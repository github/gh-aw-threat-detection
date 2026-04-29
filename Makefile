.PHONY: build test lint clean docker-build docker-push

BINARY_NAME=threat-detect
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/github/gh-aw-threat-detection/pkg/detector.Version=$(VERSION)"
REGISTRY?=ghcr.io/github/gh-aw-threat-detection
IMAGE_TAG?=$(VERSION)

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/threat-detect

test:
	go test -v -race ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	go vet ./...

clean:
	rm -rf bin/ coverage.out coverage.html

docker-build:
	docker build -t $(REGISTRY):$(IMAGE_TAG) .

docker-push:
	docker push $(REGISTRY):$(IMAGE_TAG)

all: lint test build
