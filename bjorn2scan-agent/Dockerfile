# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /workspace

# Copy scanner-core first (shared dependency)
COPY scanner-core/ ./scanner-core/

# Copy bjorn2scan-agent
WORKDIR /workspace/bjorn2scan-agent
COPY bjorn2scan-agent/go.mod bjorn2scan-agent/go.sum* ./
RUN go mod download

COPY bjorn2scan-agent/main.go ./
COPY bjorn2scan-agent/docker/ ./docker/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o bjorn2scan-agent .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /workspace/bjorn2scan-agent/bjorn2scan-agent /bjorn2scan-agent

EXPOSE 9999

ENTRYPOINT ["/bjorn2scan-agent"]
