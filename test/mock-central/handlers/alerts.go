package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// Alert represents a simplified alert structure for filtering
type Alert struct {
	ID               string                 `json:"id"`
	Policy           map[string]interface{} `json:"policy"`
	Deployment       map[string]interface{} `json:"deployment"`
	Resource         map[string]interface{} `json:"resource"`
	CommonEntityInfo map[string]interface{} `json:"commonEntityInfo"`
	LifecycleStage   string                 `json:"lifecycleStage"`
	State            string                 `json:"state"`
	Time             string                 `json:"time"`
	Raw              json.RawMessage        // Store original JSON for output
}

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

		// Parse query filters
		queryStr := query.Get("query")
		filters := ParseQuery(queryStr)

		// Parse the JSON to apply filtering
		var alertsResponse struct {
			Alerts []json.RawMessage `json:"alerts"`
		}

		if err := json.Unmarshal(data, &alertsResponse); err != nil {
			http.Error(w, "Failed to parse alerts data", http.StatusInternalServerError)
			return
		}

		// Parse alerts and apply filters, extracting time for efficient sorting
		type alertWithTime struct {
			raw  json.RawMessage
			time string
		}
		var filteredAlerts []alertWithTime

		for i, alertJSON := range alertsResponse.Alerts {
			var alert Alert
			if err := json.Unmarshal(alertJSON, &alert); err != nil {
				continue
			}
			alert.Raw = alertJSON

			// Apply filters
			if !matchesAlertFilters(alert, filters) {
				continue
			}

			filteredAlerts = append(filteredAlerts, alertWithTime{
				raw:  alert.Raw,
				time: alert.Time,
			})
		}

		// Sort by time (newest first) if requested or by default
		sortStr := query.Get("sortOption.field")
		if sortStr == "" || sortStr == "Alert Time" {
			sort.Slice(filteredAlerts, func(i, j int) bool {
				// Newer first, so j < i
				return filteredAlerts[j].time < filteredAlerts[i].time
			})
		}

		totalAlerts := len(filteredAlerts)

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

		// Slice alerts based on pagination and extract raw JSON
		paginatedAlertsRaw := make([]json.RawMessage, end-offset)
		for i, awt := range filteredAlerts[offset:end] {
			paginatedAlertsRaw[i] = awt.raw
		}

		// Create response
		response := map[string]interface{}{
			"alerts": paginatedAlertsRaw,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// matchesAlertFilters checks if an alert matches the query filters
// Multiple filters for the SAME field are OR'd together
// Filters for DIFFERENT fields are AND'd together
func matchesAlertFilters(alert Alert, filters []QueryFilter) bool {
	// Group filters by field
	filtersByField := make(map[string][]string)
	for _, filter := range filters {
		filtersByField[filter.Field] = append(filtersByField[filter.Field], filter.Value)
	}

	// Check each field (AND across fields)
	for field, values := range filtersByField {
		matched := false

		switch field {
		case "Namespace":
			namespace := extractAlertNamespace(alert)
			// OR across multiple namespace values
			if slices.Contains(values, namespace) {
				matched = true
			}

		case "Severity":
			severity := extractAlertSeverity(alert)
			// OR across multiple severity values (MEDIUM, HIGH, CRITICAL)
			for _, value := range values {
				if strings.EqualFold(severity, value) {
					matched = true
					break
				}
			}

		case "Lifecycle Stage":
			// OR across multiple lifecycle stage values
			for _, value := range values {
				if strings.EqualFold(alert.LifecycleStage, value) {
					matched = true
					break
				}
			}

		case "Violation State":
			// OR across multiple state values
			for _, value := range values {
				if value == "ACTIVE" && strings.EqualFold(alert.State, "ACTIVE") {
					matched = true
					break
				}
			}
		}

		// If this field didn't match any of its values, fail (AND across fields)
		if !matched {
			return false
		}
	}

	return true
}

// extractAlertNamespace extracts the namespace from an alert
func extractAlertNamespace(alert Alert) string {
	// Check deployment first
	if alert.Deployment != nil {
		if ns, ok := alert.Deployment["namespace"].(string); ok && ns != "" {
			return ns
		}
	}
	// Check common entity info
	if alert.CommonEntityInfo != nil {
		if ns, ok := alert.CommonEntityInfo["namespace"].(string); ok && ns != "" {
			return ns
		}
	}
	return ""
}

// extractAlertSeverity extracts the severity from an alert's policy
func extractAlertSeverity(alert Alert) string {
	if alert.Policy != nil {
		if severity, ok := alert.Policy["severity"].(string); ok {
			// Normalize severity (remove _SEVERITY suffix if present)
			severity = strings.ToUpper(severity)
			severity = strings.TrimSuffix(severity, "_SEVERITY")
			return severity
		}
	}
	return ""
}
