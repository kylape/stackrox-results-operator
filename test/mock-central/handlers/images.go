package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/kylape/stackrox-results-operator/test/mock-central/storage"
)

// ImageExport represents the export wrapper structure
type ImageExport struct {
	Result *ImageResult `json:"result"`
}

type ImageResult struct {
	Image json.RawMessage `json:"image"`
}

// Image represents a simplified image structure for filtering
type Image struct {
	ID       string                 `json:"id"`
	Name     map[string]interface{} `json:"name"`
	Scan     map[string]interface{} `json:"scan"`
	Metadata map[string]interface{} `json:"metadata"`
}

// NewImagesHandler returns a handler for /v1/export/images that streams NDJSON
func NewImagesHandler(store *storage.MemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get all images NDJSON
		data := store.GetImages()
		if len(data) == 0 {
			http.Error(w, "No data loaded", http.StatusNotFound)
			return
		}

		// Parse query filters
		query := r.URL.Query()
		queryStr := query.Get("query")
		filters := ParseQuery(queryStr)

		// Stream NDJSON line by line with filtering
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

			// Parse the export wrapper
			var exportWrapper ImageExport
			if err := json.Unmarshal(line, &exportWrapper); err != nil {
				continue
			}

			if exportWrapper.Result == nil || len(exportWrapper.Result.Image) == 0 {
				continue
			}

			// Parse the image to check filters
			var image Image
			if err := json.Unmarshal(exportWrapper.Result.Image, &image); err != nil {
				continue
			}

			// Apply filters - this both filters images AND filters CVEs within images
			filteredImage, matches := filterImage(image, filters)
			if !matches {
				continue
			}

			// Re-marshal the filtered image
			filteredImageJSON, err := json.Marshal(filteredImage)
			if err != nil {
				continue
			}

			// Create new export wrapper with filtered image
			filteredWrapper := ImageExport{
				Result: &ImageResult{
					Image: filteredImageJSON,
				},
			}

			// Marshal and write the filtered wrapper
			filteredLine, err := json.Marshal(filteredWrapper)
			if err != nil {
				continue
			}

			w.Write(filteredLine)
			w.Write([]byte("\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}

		if err := scanner.Err(); err != nil {
			// Can't send error to client at this point, just log it
			// The client will see incomplete stream
			return
		}
	}
}

// filterImage filters an image and its CVEs based on query filters
// Returns the filtered image and whether it matches the filters
func filterImage(image Image, filters []QueryFilter) (Image, bool) {
	// Extract filter values
	var minSeverityFilters []string
	fixableOnly := false

	for _, filter := range filters {
		switch filter.Field {
		case "CVE Severity":
			minSeverityFilters = append(minSeverityFilters, filter.Value)
		case "Fixable":
			if filter.Value == "true" {
				fixableOnly = true
			}
		}
	}

	// If no scan data, check if image should be filtered out
	if image.Scan == nil {
		return image, false
	}

	components, ok := image.Scan["components"].([]interface{})
	if !ok || len(components) == 0 {
		return image, false
	}

	// Determine minimum severity level (take the highest minimum from all filters)
	var minLevel SeverityLevel = SeverityUnknown
	for _, sevFilter := range minSeverityFilters {
		level := ParseSeverity(sevFilter)
		if level > minLevel {
			minLevel = level
		}
	}

	// Filter CVEs within each component
	filteredComponents := []interface{}{}
	hasAnyMatchingCVE := false

	for _, comp := range components {
		component, ok := comp.(map[string]interface{})
		if !ok {
			continue
		}

		vulns, ok := component["vulns"].([]interface{})
		if !ok {
			continue
		}

		filteredVulns := []interface{}{}
		for _, v := range vulns {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			// Check severity filter
			if minLevel > SeverityUnknown {
				severity, ok := vuln["severity"].(string)
				if !ok {
					continue
				}
				vulnLevel := ParseSeverity(severity)
				if vulnLevel < minLevel {
					continue // Skip CVEs below minimum severity
				}
			}

			// Check fixable filter
			if fixableOnly {
				isFixable := false
				if setFixedBy, ok := vuln["setFixedBy"].(map[string]interface{}); ok {
					if fixedBy, ok := setFixedBy["fixedBy"].(string); ok && fixedBy != "" {
						isFixable = true
					}
				}
				if fixedBy, ok := vuln["fixedBy"].(string); ok && fixedBy != "" {
					isFixable = true
				}
				if !isFixable {
					continue // Skip non-fixable CVEs
				}
			}

			// CVE matches all filters
			filteredVulns = append(filteredVulns, vuln)
			hasAnyMatchingCVE = true
		}

		// Only include component if it has matching CVEs
		if len(filteredVulns) > 0 {
			// Create a copy of the component with filtered vulns
			filteredComponent := make(map[string]interface{})
			for k, v := range component {
				filteredComponent[k] = v
			}
			filteredComponent["vulns"] = filteredVulns
			filteredComponents = append(filteredComponents, filteredComponent)
		}
	}

	// If no matching CVEs found, don't include this image
	if !hasAnyMatchingCVE {
		return image, false
	}

	// Create filtered image with filtered components
	filteredImage := image
	filteredScan := make(map[string]interface{})
	for k, v := range image.Scan {
		filteredScan[k] = v
	}
	filteredScan["components"] = filteredComponents
	filteredImage.Scan = filteredScan

	return filteredImage, true
}

