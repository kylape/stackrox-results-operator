package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MemoryStore holds all mock Central data in memory
type MemoryStore struct {
	mu          sync.RWMutex
	dataDir     string
	alerts      []byte // Raw JSON
	images      []byte // Raw NDJSON
	deployments []byte // Raw JSON
	clusters    []byte // Raw JSON
	nodes       []byte // Raw JSON
}

// NewMemoryStore creates a new in-memory data store
func NewMemoryStore(dataDir string) *MemoryStore {
	return &MemoryStore{
		dataDir: dataDir,
	}
}

// LoadFromDisk loads all JSON files from the data directory if they exist
func (s *MemoryStore) LoadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files := []struct {
		name string
		dest *[]byte
	}{
		{"alerts.json", &s.alerts},
		{"images.ndjson", &s.images},
		{"deployments.json", &s.deployments},
		{"clusters.json", &s.clusters},
		{"nodes.json", &s.nodes},
	}

	for _, f := range files {
		filePath := filepath.Join(s.dataDir, f.name)
		data, err := os.ReadFile(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // File doesn't exist yet, skip
			}
			return fmt.Errorf("failed to read %s: %w", f.name, err)
		}
		*f.dest = data
	}

	return nil
}

// SaveFile saves a file to disk and updates the in-memory cache
func (s *MemoryStore) SaveFile(filename string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure data directory exists
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Save to disk
	filePath := filepath.Join(s.dataDir, filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", filename, err)
	}

	// Update in-memory cache
	switch filename {
	case "alerts.json":
		s.alerts = data
	case "images.ndjson":
		s.images = data
	case "deployments.ndjson":
		s.deployments = data
	case "clusters.json":
		s.clusters = data
	case "nodes.json":
		s.nodes = data
	default:
		return fmt.Errorf("unknown file: %s", filename)
	}

	return nil
}

// GetAlerts returns the raw alerts JSON data
func (s *MemoryStore) GetAlerts() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alerts
}

// GetImages returns the raw images NDJSON data
func (s *MemoryStore) GetImages() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.images
}

// GetClusters returns the raw clusters JSON data
func (s *MemoryStore) GetClusters() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clusters
}

// GetDeployments returns the raw deployments JSON data
func (s *MemoryStore) GetDeployments() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deployments
}

// GetNodes returns the raw nodes JSON data
func (s *MemoryStore) GetNodes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes
}
