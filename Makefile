.PHONY: help dev build test bench lint fmt vet clean install release-snapshot docker

BINARY := dvarapala
PKG    := github.com/tharvid/dvarapala
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Install dev tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/goreleaser/goreleaser/v2@latest

build: ## Build local binary
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/dvarapala

test: ## Run unit tests
	go test -race ./...

bench: ## Run benchmarks
	go test -bench=. -benchmem -run=^$$ ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format code with gofmt
	gofmt -w .

lint: vet ## Run linters (gofmt + vet + golangci-lint)
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "Files need formatting:"; echo "$$out"; exit 1; fi
	golangci-lint run ./... || true

clean: ## Remove build artifacts
	rm -rf bin dist coverage.txt coverage.html

install: build ## Install binary to GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/dvarapala

release-snapshot: ## Build snapshot release (no publish)
	goreleaser release --snapshot --clean

docker: ## Build local Docker image
	docker build -t dvarapala:dev -f packaging/docker/Dockerfile .
