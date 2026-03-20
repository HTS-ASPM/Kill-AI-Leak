# =============================================================================
# Kill AI Leak - Makefile
# =============================================================================

# Project metadata
MODULE        := github.com/kill-ai-leak/kill-ai-leak
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS       := -s -w \
                 -X main.version=$(VERSION) \
                 -X main.commit=$(COMMIT) \
                 -X main.buildTime=$(BUILD_TIME)

# Directories
BIN_DIR       := bin
CMD_DIR       := cmd
PROTO_DIR     := api/proto

# Docker
REGISTRY      ?= ghcr.io/kill-ai-leak
IMAGE_TAG     ?= $(VERSION)

# Tools (override via environment if needed)
GO            := go
GOLANGCI_LINT := golangci-lint
PROTOC        := protoc

# All binary targets under cmd/
BINARIES      := gateway api-server observer processor cli

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------

.PHONY: all
all: fmt vet lint test build

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: build
build: $(addprefix build-,$(BINARIES)) ## Build all binaries

.PHONY: $(addprefix build-,$(BINARIES))
$(addprefix build-,$(BINARIES)): build-%:
	@echo "==> Building $*..."
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$* ./$(CMD_DIR)/$*

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

.PHONY: test
test: ## Run unit tests
	@echo "==> Running tests..."
	$(GO) test -race -cover -count=1 ./...

.PHONY: test-short
test-short: ## Run tests in short mode (skip slow tests)
	$(GO) test -short -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	$(GO) test -race -tags=integration -count=1 ./tests/...

.PHONY: test-coverage
test-coverage: ## Generate HTML coverage report
	@mkdir -p $(BIN_DIR)
	$(GO) test -race -coverprofile=$(BIN_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(BIN_DIR)/coverage.out -o $(BIN_DIR)/coverage.html
	@echo "Coverage report: $(BIN_DIR)/coverage.html"

# ---------------------------------------------------------------------------
# Lint & Format
# ---------------------------------------------------------------------------

.PHONY: fmt
fmt: ## Format Go source files
	@echo "==> Formatting..."
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo "==> Vetting..."
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	@echo "==> Linting..."
	$(GOLANGCI_LINT) run ./...

# ---------------------------------------------------------------------------
# Protobuf
# ---------------------------------------------------------------------------

.PHONY: proto
proto: ## Generate Go code from protobuf definitions
	@echo "==> Generating protobuf code..."
	@find $(PROTO_DIR) -name '*.proto' -exec $(PROTOC) \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		{} +

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

.PHONY: docker-build
docker-build: docker-build-gateway docker-build-api-server docker-build-observer docker-build-processor ## Build all Docker images

.PHONY: docker-build-gateway
docker-build-gateway: ## Build the gateway Docker image
	@echo "==> Building gateway image..."
	docker build \
		-f deploy/docker/Dockerfile.gateway \
		-t $(REGISTRY)/gateway:$(IMAGE_TAG) \
		-t $(REGISTRY)/gateway:latest \
		.

.PHONY: docker-build-api-server
docker-build-api-server:
	@echo "==> Building api-server image..."
	docker build \
		-f deploy/docker/Dockerfile.gateway \
		--build-arg BINARY=api-server \
		-t $(REGISTRY)/api-server:$(IMAGE_TAG) \
		-t $(REGISTRY)/api-server:latest \
		.

.PHONY: docker-build-observer
docker-build-observer:
	@echo "==> Building observer image..."
	docker build \
		-f deploy/docker/Dockerfile.gateway \
		--build-arg BINARY=observer \
		-t $(REGISTRY)/observer:$(IMAGE_TAG) \
		-t $(REGISTRY)/observer:latest \
		.

.PHONY: docker-build-processor
docker-build-processor:
	@echo "==> Building processor image..."
	docker build \
		-f deploy/docker/Dockerfile.gateway \
		--build-arg BINARY=processor \
		-t $(REGISTRY)/processor:$(IMAGE_TAG) \
		-t $(REGISTRY)/processor:latest \
		.

.PHONY: docker-push
docker-push: ## Push all Docker images to the registry
	@echo "==> Pushing images..."
	docker push $(REGISTRY)/gateway:$(IMAGE_TAG)
	docker push $(REGISTRY)/gateway:latest
	docker push $(REGISTRY)/api-server:$(IMAGE_TAG)
	docker push $(REGISTRY)/api-server:latest
	docker push $(REGISTRY)/observer:$(IMAGE_TAG)
	docker push $(REGISTRY)/observer:latest
	docker push $(REGISTRY)/processor:$(IMAGE_TAG)
	docker push $(REGISTRY)/processor:latest

# ---------------------------------------------------------------------------
# Run (local development)
# ---------------------------------------------------------------------------

.PHONY: run-gateway
run-gateway: build-gateway ## Build and run the gateway locally
	@echo "==> Running gateway..."
	./$(BIN_DIR)/gateway --config configs/default.yaml

.PHONY: run-api-server
run-api-server: build-api-server ## Build and run the API server locally
	@echo "==> Running API server..."
	./$(BIN_DIR)/api-server --config configs/default.yaml

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	@echo "==> Cleaning..."
	rm -rf $(BIN_DIR)

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
