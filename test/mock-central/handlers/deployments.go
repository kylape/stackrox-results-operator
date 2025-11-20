package handlers

import (
	"net/http"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// NewDeploymentsHandler returns a handler for /v1/deployments
func NewDeploymentsHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get deployments data
		data := store.GetDeployments()
		if data == nil || len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		// Return JSON
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}
