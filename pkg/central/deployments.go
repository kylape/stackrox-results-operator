package central

import (
	"context"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// DeploymentsResponse represents the response from /v1/deployments
type DeploymentsResponse struct {
	Deployments []*Deployment `json:"deployments"`
}

// Deployment represents a deployment from Central
type Deployment struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Namespace  string       `json:"namespace"`
	ClusterID  string       `json:"clusterId"`
	Containers []*Container `json:"containers,omitempty"`
}

// Container represents a container in a deployment
type Container struct {
	Name  string      `json:"name"`
	Image *ImageName2 `json:"image,omitempty"`
}

// ImageName2 represents an image name (avoiding conflict with existing ImageName)
type ImageName2 struct {
	FullName string `json:"fullName,omitempty"`
	Registry string `json:"registry,omitempty"`
	Remote   string `json:"remote,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

// ListDeployments fetches deployments from Central
func (c *Client) ListDeployments(ctx context.Context) ([]*Deployment, error) {
	log.V(1).Info("Listing deployments from Central")

	resp, err := c.doRequest(ctx, "GET", "/v1/deployments")
	if err != nil {
		return nil, errors.Wrap(err, "failed to list deployments")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("list deployments failed with status %d: %s", resp.StatusCode, string(body))
	}

	var deploymentsResp DeploymentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&deploymentsResp); err != nil {
		return nil, errors.Wrap(err, "failed to decode deployments response")
	}

	log.Info("Retrieved deployments from Central", "count", len(deploymentsResp.Deployments))
	return deploymentsResp.Deployments, nil
}

// GetImagesByNamespace builds a map of namespace -> images from deployments
func GetImagesByNamespaceFromDeployments(deployments []*Deployment) map[string]map[string]bool {
	imagesByNamespace := make(map[string]map[string]bool)

	for _, deployment := range deployments {
		namespace := deployment.Namespace
		if namespace == "" {
			continue
		}

		if imagesByNamespace[namespace] == nil {
			imagesByNamespace[namespace] = make(map[string]bool)
		}

		for _, container := range deployment.Containers {
			if container.Image != nil && container.Image.FullName != "" {
				imagesByNamespace[namespace][container.Image.FullName] = true
			}
		}
	}

	return imagesByNamespace
}
