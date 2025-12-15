# scanner-core

Shared library for the bjorn2scan v2 platform, containing common functionality for scanner components.

## Overview

The scanner-core library provides reusable components and utilities that are shared across all bjorn2scan scanner implementations:
- k8s-scan-server (Kubernetes-based scanner)
- bjorn2scan-agent (Linux host agent)
- pod-scanner (Kubernetes DaemonSet scanner)

## Features

### HTTP Handlers

Common HTTP endpoint handlers for health checks and system information:

- **HealthHandler**: Returns a simple "OK" response for health checks
- **InfoHandler**: Returns component-specific information as JSON

## Usage

### Installing

Add scanner-core to your component's `go.mod`:

```go
require github.com/bvboe/b2s-go/scanner-core v0.0.0

// For local development
replace github.com/bvboe/b2s-go/scanner-core => ../scanner-core
```

### Implementing Health and Info Endpoints

**Option 1: Using the default mux (simplest)**

```go
package main

import (
    "net/http"
    "github.com/bvboe/b2s-go/scanner-core/handlers"
)

// Define your component-specific info response
type MyComponentInfo struct {
    Version string
    // ... other fields
}

// Implement the InfoProvider interface
type MyInfo struct{}

func (m *MyInfo) GetInfo() interface{} {
    return MyComponentInfo{
        Version: "1.0.0",
        // ... populate fields
    }
}

func main() {
    infoProvider := &MyInfo{}

    // Register all standard endpoints at once
    handlers.RegisterDefaultHandlers(infoProvider)

    http.ListenAndServe(":8080", nil)
}
```

**Option 2: Using a custom mux (for more control)**

```go
package main

import (
    "net/http"
    "github.com/bvboe/b2s-go/scanner-core/handlers"
)

type MyInfo struct{}

func (m *MyInfo) GetInfo() interface{} {
    return map[string]string{
        "version": "1.0.0",
        "component": "my-scanner",
    }
}

func main() {
    infoProvider := &MyInfo{}

    mux := http.NewServeMux()

    // Register all standard endpoints at once
    handlers.RegisterHandlers(mux, infoProvider)

    // You can add more custom handlers here
    mux.HandleFunc("/custom", customHandler)

    server := &http.Server{
        Addr:    ":8080",
        Handler: mux,
    }

    server.ListenAndServe()
}
```

**Option 3: Manual registration (for full control)**

```go
package main

import (
    "net/http"
    "github.com/bvboe/b2s-go/scanner-core/handlers"
)

type MyInfo struct{}

func (m *MyInfo) GetInfo() interface{} {
    return map[string]string{"version": "1.0.0"}
}

func main() {
    infoProvider := &MyInfo{}

    // Register handlers individually
    http.HandleFunc("/health", handlers.HealthHandler)
    http.HandleFunc("/info", handlers.InfoHandler(infoProvider))

    http.ListenAndServe(":8080", nil)
}
```

## Development

### Running Tests

```bash
make test
```

### Cleaning Test Cache

```bash
make clean
```

## Architecture

The scanner-core library uses a provider pattern for component-specific information. Components implement the `InfoProvider` interface to supply their specific data, while the core library handles the HTTP mechanics.

### InfoProvider Interface

```go
type InfoProvider interface {
    GetInfo() interface{}
}
```

Components implement this interface to provide their specific information structure.

## Future Extensions

Scanner-core will be extended to include:
- SBOM retrieval logic
- Scan result management
- Common data structures for vulnerabilities
- Shared utilities for workload monitoring

## License

Same open source license as bjorn2scan v1.
