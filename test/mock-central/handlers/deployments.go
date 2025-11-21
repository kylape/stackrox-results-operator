package handlers

import (
	"bufio"
	"bytes"
	"net/http"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// NewDeploymentsHandler returns a handler for /v1/export/deployments that streams NDJSON
func NewDeploymentsHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get deployments NDJSON data (export format)
		data := store.GetDeployments()
		if len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		// Stream NDJSON line by line
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Transfer-Encoding", "chunked")

		scanner := bufio.NewScanner(bytes.NewReader(data))
		// Set large buffer size to handle potentially large JSON objects (10MB per line)
		const maxScanTokenSize = 10 * 1024 * 1024
		buf := make([]byte, maxScanTokenSize)
		scanner.Buffer(buf, maxScanTokenSize)

		flusher, _ := w.(http.Flusher)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			// Write line followed by newline
			w.Write(line)
			w.Write([]byte("\n"))

			// Flush to send data immediately (streaming)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}
