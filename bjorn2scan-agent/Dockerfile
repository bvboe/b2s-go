# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY main.go ./

# Build with version injection
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -w -s" \
    -o bjorn2scan-agent .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/bjorn2scan-agent /bjorn2scan-agent

EXPOSE 9999

ENTRYPOINT ["/bjorn2scan-agent"]
