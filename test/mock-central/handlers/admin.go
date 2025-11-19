package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/kylape/stackrox-results-operator/test/mock-central/preprocessor"
	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewUploadHandler returns a handler for /admin/upload
func NewUploadHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form (max 500MB)
		if err := r.ParseMultipartForm(500 << 20); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		uploaded := []string{}

		// Expected files
		fileNames := []string{"alerts", "images", "clusters", "nodes"}

		// Process each file
		for _, fieldName := range fileNames {
			file, header, err := r.FormFile(fieldName)
			if err != nil {
				// File not provided, skip
				continue
			}
			defer file.Close()

			// Read file content
			data, err := io.ReadAll(file)
			if err != nil {
				log.Printf("Error reading file content %s: %v", header.Filename, err)
				continue
			}

			// Save to storage
			if err := store.SaveFile(header.Filename, data); err != nil {
				log.Printf("Error saving file %s: %v", header.Filename, err)
				continue
			}

			uploaded = append(uploaded, header.Filename)
			log.Printf("Uploaded: %s (%d bytes)", header.Filename, len(data))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"uploaded": uploaded,
		})
	}
}

// NewPreprocessHandler returns a handler for /admin/preprocess
func NewPreprocessHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get alerts data
		alertsData := store.GetAlerts()
		if alertsData == nil || len(alertsData) == 0 {
			http.Error(w, "No alerts data loaded", http.StatusBadRequest)
			return
		}

		// Create Kubernetes client
		config, err := rest.InClusterConfig()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create k8s config: %v", err), http.StatusInternalServerError)
			return
		}

		kubeClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create k8s client: %v", err), http.StatusInternalServerError)
			return
		}

		// Create namespaces
		if err := preprocessor.CreateNamespaces(context.Background(), kubeClient, alertsData); err != nil {
			http.Error(w, fmt.Sprintf("Preprocessing failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "Namespaces created",
		})
	}
}
