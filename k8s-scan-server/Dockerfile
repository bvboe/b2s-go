# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /workspace

# Copy scanner-core first (shared dependency)
COPY scanner-core/ ./scanner-core/

# Copy k8s-scan-server
WORKDIR /workspace/k8s-scan-server
COPY k8s-scan-server/go.mod k8s-scan-server/go.sum* ./
RUN go mod download

COPY k8s-scan-server/main.go ./
COPY k8s-scan-server/k8s/ ./k8s/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o k8s-scan-server .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/k8s-scan-server/k8s-scan-server /k8s-scan-server

EXPOSE 8080

ENTRYPOINT ["/k8s-scan-server"]
