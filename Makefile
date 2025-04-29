# Makefile for github-tag-go-modules-checker

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOFMT=gofmt
GOLINT=golangci-lint
GORUN=$(GOCMD) run
BINARY_NAME=checker
SOURCE_FILES=main.go

# Default target
all: check build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@$(GOBUILD) -o $(BINARY_NAME) $(SOURCE_FILES)
	@echo "Build complete: ./$(BINARY_NAME)"

# Format the code
fmt:
	@echo "Formatting code..."
	@$(GOLINT) fmt

# Lint the code
# Requires golangci-lint: https://golangci-lint.run/usage/install/
lint:
	@echo "Linting code..."
	@if ! command -v $(GOLINT) &> /dev/null; then \
		 echo "golangci-lint could not be found. Please install it: https://golangci-lint.run/usage/install/"; \
		 exit 1; \
	 fi
	@$(GOLINT) run

# Run linters and formatters.
check: fmt test lint

# Run the application (requires -repo flag)
run: build
	@echo "Running $(BINARY_NAME) (requires -repo flag, e.g., make run ARGS='-repo <repo_url> [-start-date YYYY-MM-DD]...')..."
	./$(BINARY_NAME) $(ARGS)

# Clean the built binary
clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)

# Help message
help:
	@echo "Available targets:"
	@echo "  all          Run check and build (default)"
	@echo "  build        Compile the application to ./$(BINARY_NAME)"
	@echo "  fmt          Format Go source files with gofmt"
	@echo "  lint         Run golangci-lint linter"
	@echo "  check        Run fmt and lint targets"
	@echo "  run          Build and run the application (pass args via ARGS='-repo <url> [-start-date DATE] [-end-date DATE] ...')"
	@echo "  clean        Remove the compiled binary"
	@echo "  help         Show this help message"

# Add test targets
test:
	@echo "Running unit tests..."
	@$(GOCMD) test ./...

test-integration:
	@echo "Running integration tests (requires built binary and GITHUB_TOKEN)..."
	@./test_integration.sh

.PHONY: all build fmt lint check run clean help test test-integration
