.PHONY: all build test test-coverage lint golint clean docker-build docker-smoke docker-push \
	check-node-version deps deps-dev tools install-golangci-lint fmt fmt-go fmt-check \
	license-check license-report security-scan security-gosec security-govulncheck \
	sbom lifecycle-validate validate-lifecycle agent-finish help

BINARY_NAME=threat-detect
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/github/gh-aw-threat-detection/pkg/detector.Version=$(VERSION)"
REGISTRY?=ghcr.io/github/gh-aw-threat-detection
IMAGE_TAG?=$(VERSION)

all: lint test build

check-node-version:
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Error: Node.js is not installed."; \
		echo "This project requires Node.js 20 or higher."; \
		exit 1; \
	fi; \
	NODE_VERSION=$$(node --version); \
	NODE_VERSION_NUM=$$(echo "$$NODE_VERSION" | sed 's/v//'); \
	NODE_MAJOR=$$(echo "$$NODE_VERSION_NUM" | cut -d. -f1); \
	if [ "$$NODE_MAJOR" -lt 20 ]; then \
		echo "Error: Node.js version $$NODE_VERSION is not supported."; \
		echo "This project requires Node.js 20 or higher."; \
		exit 1; \
	fi; \
	echo "Node.js version check passed ($$NODE_VERSION)"

deps:
	go mod download
	go mod tidy

deps-dev: deps tools install-golangci-lint
	@echo "Development dependencies installed"

tools:
	@echo "Installing build tools..."
	@go install github.com/securego/gosec/v2/cmd/gosec@v2.23.0
	@go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	@echo "Tools installed successfully"

install-golangci-lint:
	@echo "Installing golangci-lint binary..."
	@GOLANGCI_LINT_VERSION="v2.8.0"; \
	GOPATH=$$(go env GOPATH); \
	GOOS=$$(go env GOOS); \
	GOARCH=$$(go env GOARCH); \
	BINARY_NAME="golangci-lint"; \
	if [ "$$GOOS" = "windows" ]; then \
		BINARY_NAME="golangci-lint.exe"; \
	fi; \
	if [ -x "$$GOPATH/bin/$$BINARY_NAME" ]; then \
		INSTALLED_VERSION=$$("$$GOPATH/bin/$$BINARY_NAME" version --short 2>/dev/null || echo "unknown"); \
		if [ "$$INSTALLED_VERSION" = "$${GOLANGCI_LINT_VERSION#v}" ]; then \
			echo "golangci-lint $$GOLANGCI_LINT_VERSION already installed"; \
			exit 0; \
		fi; \
	fi; \
	DOWNLOAD_URL="https://github.com/golangci/golangci-lint/releases/download/$$GOLANGCI_LINT_VERSION/golangci-lint-$${GOLANGCI_LINT_VERSION#v}-$$GOOS-$$GOARCH.tar.gz"; \
	TEMP_DIR=$$(mktemp -d); \
	trap "rm -rf $$TEMP_DIR" EXIT; \
	echo "Downloading golangci-lint $$GOLANGCI_LINT_VERSION for $$GOOS/$$GOARCH..."; \
	if curl -sSL "$$DOWNLOAD_URL" | tar -xz -C "$$TEMP_DIR"; then \
		mkdir -p "$$GOPATH/bin"; \
		mv "$$TEMP_DIR"/golangci-lint-*/$$BINARY_NAME "$$GOPATH/bin/$$BINARY_NAME"; \
		chmod +x "$$GOPATH/bin/$$BINARY_NAME"; \
		echo "golangci-lint $$GOLANGCI_LINT_VERSION installed to $$GOPATH/bin/$$BINARY_NAME"; \
	else \
		echo "Error: Failed to download golangci-lint from $$DOWNLOAD_URL"; \
		exit 1; \
	fi

fmt: fmt-go
	@echo "Code formatted successfully"

fmt-go:
	@echo "Formatting Go code..."
	@go fmt ./...
	@echo "Go code formatted"

fmt-check:
	@unformatted=$$(gofmt -l $$(find . -path './tmp' -prune -o -name '*.go' -print)); \
	if [ -n "$$unformatted" ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/threat-detect

test:
	go test -v -race ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lifecycle-validate:
	go test ./pkg/detector -run TestThreatDetectionLifecycleRegistry -count=1

lint:
	go vet ./...

validate-lifecycle:
	$(MAKE) lifecycle-validate

golint:
	@GOPATH=$$(go env GOPATH); \
	if command -v golangci-lint >/dev/null 2>&1 || [ -x "$$GOPATH/bin/golangci-lint" ]; then \
		PATH="$$GOPATH/bin:$$PATH" golangci-lint run ./cmd/... ./pkg/...; \
	else \
		echo "golangci-lint is not installed. Run 'make deps-dev' to install dependencies."; \
		exit 1; \
	fi

license-check:
	@echo "Checking dependency licenses..."
	@command -v go-licenses >/dev/null || go install github.com/google/go-licenses@latest
	@go-licenses check --disallowed_types=forbidden,reciprocal,restricted,unknown ./...
	@echo "License check passed"

license-report:
	@echo "Generating license report..."
	@command -v go-licenses >/dev/null || go install github.com/google/go-licenses@latest
	@go-licenses csv ./... > licenses.csv 2>&1 || true
	@echo "Report saved to licenses.csv"

security-scan: security-gosec security-govulncheck
	@echo "All security scans completed"

security-gosec:
	@echo "Running gosec security scanner..."
	@command -v gosec >/dev/null || go install github.com/securego/gosec/v2/cmd/gosec@v2.23.0
	@GOPATH=$$(go env GOPATH); \
	PATH="$$GOPATH/bin:$$PATH" gosec -fmt=json -out=gosec-report.json -stdout -exclude-generated ./...
	@echo "Gosec scan complete (results in gosec-report.json)"

security-govulncheck:
	@echo "Running govulncheck..."
	@command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	@GOPATH=$$(go env GOPATH); \
	PATH="$$GOPATH/bin:$$PATH" govulncheck ./...
	@echo "Govulncheck complete"

clean:
	rm -rf bin/ coverage.out coverage.html
	rm -f licenses.csv sbom.spdx.json sbom.cdx.json gosec-report.json

docker-build:
	docker build --build-arg VERSION=$(IMAGE_TAG) -t $(REGISTRY):$(IMAGE_TAG) .

docker-smoke: docker-build
	# Verify Alpine's standard CA bundle path exists for HTTPS-enabled engine CLIs.
	docker run --rm --entrypoint /bin/sh $(REGISTRY):$(IMAGE_TAG) -c 'test -s /etc/ssl/certs/ca-certificates.crt'
	docker run --rm $(REGISTRY):$(IMAGE_TAG) --version

docker-push:
	docker push $(REGISTRY):$(IMAGE_TAG)

sbom:
	@if ! command -v syft >/dev/null 2>&1; then \
		echo "Error: syft is not installed."; \
		echo "Install syft to generate SBOMs:"; \
		echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"; \
		exit 1; \
	fi
	@echo "Generating SBOM in SPDX format..."
	syft packages . -o spdx-json=sbom.spdx.json
	@echo "Generating SBOM in CycloneDX format..."
	syft packages . -o cyclonedx-json=sbom.cdx.json
	@echo "SBOM files generated: sbom.spdx.json, sbom.cdx.json"

agent-finish: deps-dev fmt lint build test security-scan
	@echo "Agent finished tasks successfully."

help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  test           - Run Go tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  fmt            - Format Go code"
	@echo "  fmt-check      - Validate Go formatting"
	@echo "  lint           - Run go vet"
	@echo "  golint         - Run golangci-lint"
	@echo "  deps           - Download and tidy Go modules"
	@echo "  deps-dev       - Install development dependencies and tools"
	@echo "  license-check  - Check dependency license compatibility"
	@echo "  license-report - Generate CSV license report"
	@echo "  security-scan  - Run gosec and govulncheck"
	@echo "  sbom           - Generate SPDX and CycloneDX SBOMs"
	@echo "  lifecycle-validate - Validate threat detection lifecycle metadata"
	@echo "  validate-lifecycle - Alias for lifecycle-validate"
	@echo "  docker-build   - Build the Docker image"
	@echo "  docker-smoke   - Build the Docker image and run a CLI smoke test"
	@echo "  docker-push    - Push the Docker image"
	@echo "  clean          - Remove build artifacts and reports"
	@echo "  agent-finish   - Run the maintainer validation workflow"
