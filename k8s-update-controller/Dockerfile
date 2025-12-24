# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

# Copy go mod files from subdirectory (context is root)
COPY k8s-update-controller/go.mod k8s-update-controller/go.sum ./
RUN go mod download

# Copy source code from subdirectory
COPY k8s-update-controller/ .

# Build the binary
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION}" \
    -o k8s-update-controller \
    .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

# Copy the binary from builder
COPY --from=builder /build/k8s-update-controller /usr/local/bin/k8s-update-controller

# Run as non-root (UID 65532 is 'nonroot' user in Chainguard images)
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/k8s-update-controller"]
