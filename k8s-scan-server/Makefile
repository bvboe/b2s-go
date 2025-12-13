.PHONY: help build test clean docker-build

# Variables
BINARY_NAME=k8s-scan-server
IMAGE_NAME?=k8s-scan-server
IMAGE_TAG?=latest

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go binary
	go build -v -o $(BINARY_NAME) .

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)

docker-build: ## Build Docker image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
