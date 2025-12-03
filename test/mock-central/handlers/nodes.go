package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// NewClustersHandler returns a handler for /v1/clusters
func NewClustersHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		data := store.GetClusters()
		if data == nil || len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}

// NewNodesHandler returns a handler for /v1/nodes/{clusterID}
func NewNodesHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract cluster ID from path: /v1/nodes/{clusterID}
		clusterID := strings.TrimPrefix(r.URL.Path, "/v1/nodes/")
		if clusterID == "" || clusterID == r.URL.Path {
			http.Error(w, "Missing cluster ID", http.StatusBadRequest)
			return
		}

		// Get all nodes data
		data := store.GetNodes()
		if data == nil || len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		// Parse query filters
		query := r.URL.Query()
		queryStr := query.Get("query")
		filters := ParseQuery(queryStr)

		// Parse nodes data to filter by cluster
		var allNodes struct {
			Nodes []map[string]interface{} `json:"nodes"`
		}
		if err := json.Unmarshal(data, &allNodes); err != nil {
			http.Error(w, "Invalid nodes data", http.StatusInternalServerError)
			return
		}

		// Filter nodes for this cluster and apply query filters
		filteredNodes := []map[string]interface{}{}
		for _, node := range allNodes.Nodes {
			// Filter by cluster ID
			if nodeClusterID, ok := node["clusterId"].(string); ok && nodeClusterID == clusterID {
				// Apply additional query filters
				if matchesNodeFilters(node, filters) {
					filteredNodes = append(filteredNodes, node)
				}
			}
		}

		// Return filtered nodes
		response := map[string]interface{}{
			"nodes": filteredNodes,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// matchesNodeFilters checks if a node matches the query filters
func matchesNodeFilters(node map[string]interface{}, filters []QueryFilter) bool {
	for _, filter := range filters {
		switch filter.Field {
		case "CVE Severity":
			// Check if node has at least one CVE with the specified severity or higher
			if !nodeHasCVESeverity(node, filter.Value) {
				return false
			}
		}
	}
	return true
}

// nodeHasCVESeverity checks if a node has at least one CVE with the specified severity or higher
func nodeHasCVESeverity(node map[string]interface{}, minSeverity string) bool {
	scan, ok := node["scan"].(map[string]interface{})
	if !ok {
		return false
	}

	components, ok := scan["components"].([]interface{})
	if !ok {
		return false
	}

	minLevel := ParseSeverity(minSeverity)

	for _, comp := range components {
		component, ok := comp.(map[string]interface{})
		if !ok {
			continue
		}

		vulns, ok := component["vulnerabilities"].([]interface{})
		if !ok {
			continue
		}

		for _, v := range vulns {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			severity, ok := vuln["severity"].(string)
			if !ok {
				continue
			}

			vulnLevel := ParseSeverity(severity)
			if vulnLevel >= minLevel {
				return true
			}
		}
	}

	return false
}
