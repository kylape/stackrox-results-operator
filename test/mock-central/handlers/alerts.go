package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// NewAlertsHandler returns a handler for /v1/alerts
func NewAlertsHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get all alerts
		data := store.GetAlerts()
		if data == nil || len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		// Parse pagination parameters
		query := r.URL.Query()
		limit := 1000 // default limit
		offset := 0

		if limitStr := query.Get("pagination.limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				limit = l
			}
		}

		if offsetStr := query.Get("pagination.offset"); offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		// Parse the JSON to apply pagination
		var alertsResponse struct {
			Alerts []json.RawMessage `json:"alerts"`
		}

		if err := json.Unmarshal(data, &alertsResponse); err != nil {
			http.Error(w, "Failed to parse alerts data", http.StatusInternalServerError)
			return
		}

		totalAlerts := len(alertsResponse.Alerts)

		// Apply offset
		if offset >= totalAlerts {
			// Return empty result if offset is beyond available data
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"alerts":[]}`))
			return
		}

		// Calculate end index
		end := offset + limit
		if end > totalAlerts {
			end = totalAlerts
		}

		// Slice alerts based on pagination
		paginatedAlerts := alertsResponse.Alerts[offset:end]

		// Create response
		response := map[string]interface{}{
			"alerts": paginatedAlerts,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
