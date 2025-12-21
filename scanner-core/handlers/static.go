package handlers

import (
	"io/fs"
	"log"
	"net/http"

	scanner_core "github.com/bvboe/b2s-go/scanner-core"
)

// RegisterStaticHandlers registers handlers for serving the embedded web UI
func RegisterStaticHandlers(mux *http.ServeMux) {
	// Get the static subdirectory from embedded FS
	staticFS, err := fs.Sub(scanner_core.WebContent, "static")
	if err != nil {
		log.Printf("Warning: failed to access embedded static content: %v", err)
		return
	}

	// Serve the embedded files at root
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/", fileServer)

	log.Println("Static web UI registered at /")
}
