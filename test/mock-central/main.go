package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kylape/stackrox-results-operator/test/mock-central/handlers"
	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	// Initialize in-memory storage
	store := storage.NewMemoryStore(dataDir)

	// Load existing data files if present
	if err := store.LoadFromDisk(); err != nil {
		log.Printf("Warning: Could not load existing data: %v", err)
	} else {
		log.Printf("Loaded existing data from %s", dataDir)
	}

	// Setup routes
	mux := http.NewServeMux()

	// Central API endpoints (no auth, no filtering)
	mux.HandleFunc("/v1/alerts", handlers.NewAlertsHandler(store))
	mux.HandleFunc("/v1/export/images", handlers.NewImagesHandler(store))
	mux.HandleFunc("/v1/deployments", handlers.NewDeploymentsHandler(store))
	mux.HandleFunc("/v1/clusters", handlers.NewClustersHandler(store))
	mux.HandleFunc("/v1/nodes/", handlers.NewNodesHandler(store))
	mux.HandleFunc("/v1/ping", handlers.PingHandler)

	// Admin endpoints for data management
	mux.HandleFunc("/admin/upload", handlers.NewUploadHandler(store))
	mux.HandleFunc("/admin/preprocess", handlers.NewPreprocessHandler(store))

	log.Println("====================================")
	log.Println("Mock StackRox Central Server")
	log.Println("====================================")
	log.Printf("Port: %s", port)
	log.Printf("Data directory: %s", dataDir)
	log.Println("")
	log.Println("API Endpoints:")
	log.Println("  GET  /v1/ping               - Health check")
	log.Println("  GET  /v1/alerts             - List alerts")
	log.Println("  GET  /v1/export/images      - Export images (NDJSON)")
	log.Println("  GET  /v1/deployments        - List deployments")
	log.Println("  GET  /v1/clusters           - List clusters")
	log.Println("  GET  /v1/nodes/{clusterID}  - List nodes for cluster")
	log.Println("")
	log.Println("Admin Endpoints:")
	log.Println("  POST /admin/upload          - Upload data files")
	log.Println("  POST /admin/preprocess      - Create namespaces from alerts")
	log.Println("")
	log.Println("Starting server...")
	log.Println("====================================")

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
