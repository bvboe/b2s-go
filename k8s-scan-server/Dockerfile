# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /workspace

# Copy go.mod and go.sum files first for better layer caching
# This layer will only be invalidated when dependencies change
COPY scanner-core/go.mod scanner-core/go.sum ./scanner-core/
COPY k8s-scan-server/go.mod k8s-scan-server/go.sum* ./k8s-scan-server/

# Download dependencies (cached unless go.mod/go.sum changes)
WORKDIR /workspace/scanner-core
RUN go mod download

WORKDIR /workspace/k8s-scan-server
RUN go mod download

# Now copy source code (after dependency layers are cached)
WORKDIR /workspace
COPY scanner-core/ ./scanner-core/

WORKDIR /workspace/k8s-scan-server
COPY k8s-scan-server/main.go ./
COPY k8s-scan-server/k8s/ ./k8s/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o k8s-scan-server .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/k8s-scan-server/k8s-scan-server /k8s-scan-server

EXPOSE 8080

ENTRYPOINT ["/k8s-scan-server"]
