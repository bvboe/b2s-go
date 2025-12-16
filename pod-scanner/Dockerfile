# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /workspace

# Copy go.mod and go.sum files first for better layer caching
# This layer will only be invalidated when dependencies change
COPY scanner-core/go.mod scanner-core/go.sum ./scanner-core/
COPY pod-scanner/go.mod pod-scanner/go.sum* ./pod-scanner/

# Download dependencies (cached unless go.mod/go.sum changes)
WORKDIR /workspace/scanner-core
RUN go mod download

WORKDIR /workspace/pod-scanner
RUN go mod download

# Now copy source code (after dependency layers are cached)
WORKDIR /workspace
COPY scanner-core/ ./scanner-core/

WORKDIR /workspace/pod-scanner
COPY pod-scanner/main.go ./
COPY pod-scanner/runtime/ ./runtime/
COPY pod-scanner/handlers/ ./handlers/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o pod-scanner .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/pod-scanner/pod-scanner /pod-scanner

EXPOSE 8081

ENTRYPOINT ["/pod-scanner"]
