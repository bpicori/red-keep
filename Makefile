BINARY_NAME := red-keep
BUILD_DIR := bin
CMD_PATH := ./cmd/red-keep
VERSION := 0.1.0

GO := go
GOFLAGS :=

.PHONY: all build run clean vet test fmt integration-test integration-test-linux help

all: build

## build: Compile the binary to bin/
build:
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

## run: Build and run with sample args (override ARGS to customise)
ARGS ?= help
run: build
	./$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

## clean: Remove build artefacts
clean:
	rm -rf $(BUILD_DIR)

## vet: Run go vet on all packages
vet:
	$(GO) vet ./...

## test: Run all tests
test:
	$(GO) test ./...

## integration-test: Run integration tests (macOS)
integration-test-macos: build
	bash tests/integration_macos.sh

## integration-test-linux: Run integration tests (Linux)
integration-test-linux: build
	bash tests/integration_linux.sh

## fmt: Format all Go source files
fmt:
	$(GO) fmt ./...

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
