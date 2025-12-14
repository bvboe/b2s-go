# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -w -s" -o k8s-scan-server .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/k8s-scan-server /k8s-scan-server

EXPOSE 8080

ENTRYPOINT ["/k8s-scan-server"]
