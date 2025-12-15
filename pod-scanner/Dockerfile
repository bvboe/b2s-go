# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /workspace

# Copy scanner-core first (shared dependency)
COPY scanner-core/ ./scanner-core/

# Copy pod-scanner
WORKDIR /workspace/pod-scanner
COPY pod-scanner/go.mod pod-scanner/go.sum* ./
RUN go mod download

COPY pod-scanner/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o pod-scanner .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/pod-scanner/pod-scanner /pod-scanner

EXPOSE 8081

ENTRYPOINT ["/pod-scanner"]
