package debug

import (
	"log"
	"net/http"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code and response size.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// Write captures the response size.
func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// LoggingMiddleware provides verbose HTTP request/response logging and metrics collection
// when debug mode is enabled. When disabled, it passes through with zero overhead.
//
// Logged information includes:
//   - Request: method, path, remote address
//   - Response: status code, size, duration
//
// Example output:
//
//	[DEBUG] Request: method=GET path=/api/images remote=127.0.0.1:54321
//	[DEBUG] Response: method=GET path=/api/images status=200 size=1234 duration=45.2ms
func LoggingMiddleware(debugConfig *DebugConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If debug not enabled, pass through immediately with zero overhead
		if !debugConfig.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Log request
		log.Printf("[DEBUG] Request: method=%s path=%s remote=%s",
			r.Method, r.URL.Path, r.RemoteAddr)

		// Wrap response writer to capture status and size
		rw := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK, // Default status if WriteHeader not called
		}

		// Call next handler
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// Log response
		log.Printf("[DEBUG] Response: method=%s path=%s status=%d size=%d duration=%v",
			r.Method, r.URL.Path, rw.status, rw.size, duration)

		// Record metrics
		debugConfig.RecordRequest(r.URL.Path, duration)
	})
}
