# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

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
