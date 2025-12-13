# Build stage
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o pod-scanner .

# Runtime stage
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /app/pod-scanner /pod-scanner

EXPOSE 8081

ENTRYPOINT ["/pod-scanner"]
