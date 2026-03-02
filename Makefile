# CSVSA Makefile
# Build automation for Container Security Vulnerability Scanner Analyzer

# Build variables
BINARY_NAME=csvsa
VERSION?=1.0.0
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Directories
CMD_DIR=./cmd/csvsa
BUILD_DIR=./build
COVERAGE_DIR=./coverage

# Platforms for cross-compilation
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build clean test coverage lint fmt vet deps help

# Default target
all: clean deps test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BINARY_NAME)"

# Build for all platforms
build-all: clean
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-$${platform%/*}-$${platform#*/}$(if $(findstring windows,$${platform%/*}),.exe,) $(CMD_DIR); \
		echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-$${platform%/*}-$${platform#*/}"; \
	done
	@echo "All builds complete"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	$(GOTEST) -race -v ./...

# Generate coverage report
coverage:
	@echo "Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed" && exit 1)
	golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(LDFLAGS) $(CMD_DIR)
	@echo "Install complete"

# Run the application (example usage)
run:
	@echo "Running $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)
	./$(BINARY_NAME) --help

# Generate documentation
docs:
	@echo "Generating documentation..."
	$(GOCMD) doc -all ./... > docs/api.txt
	@echo "Documentation generated"

# Show help
help:
	@echo "CSVSA - Container Security Vulnerability Scanner Analyzer"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Clean, download deps, test, and build"
	@echo "  build      - Build the binary"
	@echo "  build-all  - Build for all platforms"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests"
	@echo "  test-race  - Run tests with race detection"
	@echo "  coverage   - Generate coverage report"
	@echo "  lint       - Run golangci-lint"
	@echo "  fmt        - Format code"
	@echo "  vet        - Run go vet"
	@echo "  deps       - Download dependencies"
	@echo "  install    - Install the binary"
	@echo "  run        - Build and run help"
	@echo "  help       - Show this help"
