package central

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"google.golang.org/protobuf/encoding/protojson"
)

// ExportDeploymentsResponse represents the response from /v1/export/deployments
type ExportDeploymentsResponse struct {
	Result *ExportDeploymentsResult `json:"result"`
}

type ExportDeploymentsResult struct {
	Deployment json.RawMessage `json:"deployment"`
}

// ListDeployments fetches deployments from Central using the export API
func (c *Client) ListDeployments(ctx context.Context) ([]*storage.Deployment, error) {
	log.V(1).Info("Listing deployments from Central")

	// Use export API which includes container information
	resp, err := c.doRequest(ctx, "GET", "/v1/export/deployments")
	if err != nil {
		return nil, errors.Wrap(err, "failed to export deployments")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("export deployments failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse newline-delimited JSON stream
	var deployments []*storage.Deployment
	scanner := bufio.NewScanner(resp.Body)

	// Increase buffer size for large deployment data
	const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Step 1: Parse wrapper JSON structure
		var exportResp ExportDeploymentsResponse
		if err := json.Unmarshal(line, &exportResp); err != nil {
			log.Error(err, "Failed to parse export deployment wrapper", "line", string(line[:min(len(line), 200)]))
			continue
		}

		if exportResp.Result == nil || len(exportResp.Result.Deployment) == 0 {
			continue
		}

		// Step 2: Parse the deployment proto from raw bytes
		deployment := &storage.Deployment{}
		if err := protojson.Unmarshal(exportResp.Result.Deployment, deployment); err != nil {
			log.Error(err, "Failed to parse deployment protobuf")
			continue
		}

		if deployment.GetId() == "" {
			continue
		}

		deployments = append(deployments, deployment)
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to read export stream")
	}

	log.Info("Retrieved deployments from Central", "count", len(deployments))
	return deployments, nil
}

// GetImagesByNamespace builds a map of namespace -> images from deployments
func GetImagesByNamespaceFromDeployments(deployments []*storage.Deployment) map[string]map[string]bool {
	imagesByNamespace := make(map[string]map[string]bool)

	for _, deployment := range deployments {
		namespace := deployment.GetNamespace()
		if namespace == "" {
			continue
		}

		if imagesByNamespace[namespace] == nil {
			imagesByNamespace[namespace] = make(map[string]bool)
		}

		for _, container := range deployment.GetContainers() {
			if container.GetImage() != nil && container.GetImage().GetName() != nil {
				fullName := container.GetImage().GetName().GetFullName()
				if fullName != "" {
					imagesByNamespace[namespace][fullName] = true
				}
			}
		}
	}

	return imagesByNamespace
}
