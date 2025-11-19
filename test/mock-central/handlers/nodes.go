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

		// Parse nodes data to filter by cluster
		var allNodes struct {
			Nodes []map[string]interface{} `json:"nodes"`
		}
		if err := json.Unmarshal(data, &allNodes); err != nil {
			http.Error(w, "Invalid nodes data", http.StatusInternalServerError)
			return
		}

		// Filter nodes for this cluster
		filteredNodes := []map[string]interface{}{}
		for _, node := range allNodes.Nodes {
			if nodeClusterID, ok := node["clusterId"].(string); ok && nodeClusterID == clusterID {
				filteredNodes = append(filteredNodes, node)
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
