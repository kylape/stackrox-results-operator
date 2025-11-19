package handlers

import (
	"net/http"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// NewAlertsHandler returns a handler for /v1/alerts
func NewAlertsHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get all alerts (no filtering)
		data := store.GetAlerts()
		if data == nil || len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}
