.PHONY: build docker-build docker-push clean test integration-test integration-test-kind integration-test-minikube help helm-lint helm-template helm-install helm-upgrade helm-uninstall

# Variables
BINARY_NAME=k8s-scan-server
IMAGE_NAME?=k8s-scan-server
IMAGE_TAG?=latest
NAMESPACE?=default
HELM_RELEASE?=bjorn2scan
HELM_CHART=./helm/bjorn2scan

help:
	@echo "Available targets:"
	@echo "  build              - Build the Go binary locally"
	@echo "  test               - Run unit tests"
	@echo "  integration-test   - Run integration tests (requires deployed service)"
	@echo "  integration-test-kind - Run full integration test on kind cluster"
	@echo "  integration-test-minikube - Run full integration test on minikube cluster"
	@echo "  docker-build       - Build the Docker image"
	@echo "  docker-push        - Push the Docker image"
	@echo "  clean              - Clean build artifacts"
	@echo ""
	@echo "Helm targets:"
	@echo "  helm-lint          - Lint the Helm chart"
	@echo "  helm-template      - Render Helm templates locally"
	@echo "  helm-install       - Install the Helm chart"
	@echo "  helm-upgrade       - Upgrade the Helm release"
	@echo "  helm-uninstall     - Uninstall the Helm release"
	@echo "  helm-kind-deploy   - Quick deploy to kind using Helm"
	@echo "  helm-minikube-deploy - Quick deploy to minikube using Helm"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE_NAME     - Docker image name (default: k8s-scan-server)"
	@echo "  IMAGE_TAG      - Docker image tag (default: latest)"
	@echo "  NAMESPACE      - Kubernetes namespace (default: default)"
	@echo "  HELM_RELEASE   - Helm release name (default: bjorn2scan)"

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

test:
	@echo "Running tests..."
	go test -v ./...

docker-build:
	@echo "Building Docker image $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-push:
	@echo "Pushing Docker image $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	go clean

# Helm targets
helm-lint:
	@echo "Linting Helm chart..."
	helm lint $(HELM_CHART)

helm-template:
	@echo "Rendering Helm templates..."
	helm template $(HELM_RELEASE) $(HELM_CHART) --namespace $(NAMESPACE)

helm-install: helm-lint
	@echo "Installing Helm chart $(HELM_RELEASE) to namespace $(NAMESPACE)..."
	helm install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG)

helm-upgrade:
	@echo "Upgrading Helm release $(HELM_RELEASE) in namespace $(NAMESPACE)..."
	helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG)

helm-uninstall:
	@echo "Uninstalling Helm release $(HELM_RELEASE) from namespace $(NAMESPACE)..."
	helm uninstall $(HELM_RELEASE) --namespace $(NAMESPACE)

# Quick Helm deploy for kind (build + load + install/upgrade)
helm-kind-deploy: docker-build
	@echo "Loading image into kind cluster..."
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG)
	@if helm list -n $(NAMESPACE) | grep -q $(HELM_RELEASE); then \
		$(MAKE) helm-upgrade; \
	else \
		$(MAKE) helm-install; \
	fi

# Quick Helm deploy for minikube (build + load + install/upgrade)
helm-minikube-deploy: docker-build
	@echo "Loading image into minikube..."
	minikube image load $(IMAGE_NAME):$(IMAGE_TAG)
	@if helm list -n $(NAMESPACE) | grep -q $(HELM_RELEASE); then \
		$(MAKE) helm-upgrade; \
	else \
		$(MAKE) helm-install; \
	fi

# Integration test targets
integration-test:
	@echo "Running integration tests..."
	@echo "Note: This assumes the service is already deployed and accessible"
	cd test/integration && SERVICE_URL=${SERVICE_URL:-http://localhost:8080} go test -v -timeout 5m ./...

integration-test-kind: docker-build
	@echo "Running full integration test on kind cluster..."
	@echo "1. Setting up kind cluster..."
	@kind create cluster --name integration-test 2>/dev/null || true
	@echo "2. Loading Docker image..."
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name integration-test
	@echo "3. Installing Helm chart..."
	helm install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		--wait --timeout 2m
	@echo "4. Waiting for pod to be ready..."
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=bjorn2scan -n $(NAMESPACE) --timeout=120s
	@echo "5. Setting up port-forward..."
	@kubectl port-forward -n $(NAMESPACE) svc/$(HELM_RELEASE) 8080:8080 > /dev/null 2>&1 & \
		echo $$! > /tmp/port-forward.pid; \
		sleep 3
	@echo "6. Running integration tests..."
	@cd test/integration && SERVICE_URL=http://localhost:8080 go test -v -timeout 5m ./...; \
		TEST_RESULT=$$?; \
		echo "7. Cleaning up..."; \
		kill `cat /tmp/port-forward.pid` 2>/dev/null || true; \
		helm uninstall $(HELM_RELEASE) -n $(NAMESPACE) || true; \
		kind delete cluster --name integration-test || true; \
		exit $$TEST_RESULT

integration-test-minikube: docker-build
	@echo "Running full integration test on minikube cluster..."
	@echo "1. Starting minikube (if not running)..."
	@minikube start 2>/dev/null || true
	@echo "2. Loading Docker image..."
	minikube image load $(IMAGE_NAME):$(IMAGE_TAG)
	@echo "3. Installing Helm chart..."
	helm install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set image.repository=$(IMAGE_NAME) \
		--set image.tag=$(IMAGE_TAG) \
		--wait --timeout 2m
	@echo "4. Waiting for pod to be ready..."
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=bjorn2scan -n $(NAMESPACE) --timeout=120s
	@echo "5. Setting up port-forward..."
	@kubectl port-forward -n $(NAMESPACE) svc/$(HELM_RELEASE) 8080:8080 > /dev/null 2>&1 & \
		echo $$! > /tmp/port-forward.pid; \
		sleep 3
	@echo "6. Running integration tests..."
	@cd test/integration && SERVICE_URL=http://localhost:8080 go test -v -timeout 5m ./...; \
		TEST_RESULT=$$?; \
		echo "7. Cleaning up..."; \
		kill `cat /tmp/port-forward.pid` 2>/dev/null || true; \
		helm uninstall $(HELM_RELEASE) -n $(NAMESPACE) || true; \
		exit $$TEST_RESULT
