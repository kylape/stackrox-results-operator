package preprocessor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AlertData represents the structure of alerts.json
type AlertData struct {
	Alerts []struct {
		Deployment *struct {
			Namespace string `json:"namespace"`
		} `json:"deployment"`
		CommonEntityInfo *struct {
			Namespace string `json:"namespace"`
		} `json:"commonEntityInfo"`
	} `json:"alerts"`
}

// DeploymentExportLine represents one line from deployments.ndjson
type DeploymentExportLine struct {
	Result *struct {
		Deployment *struct {
			Namespace string `json:"namespace"`
		} `json:"deployment"`
	} `json:"result"`
}

// CreateNamespaces extracts namespaces from alerts and deployments data and creates them in Kubernetes
func CreateNamespaces(ctx context.Context, kubeClient kubernetes.Interface, alertsJSON, deploymentsNDJSON []byte) error {
	namespaces := make(map[string]bool)

	// Extract namespaces from alerts
	if len(alertsJSON) > 0 {
		var data AlertData
		if err := json.Unmarshal(alertsJSON, &data); err != nil {
			return fmt.Errorf("failed to parse alerts JSON: %w", err)
		}

		for _, alert := range data.Alerts {
			// Try deployment namespace first
			if alert.Deployment != nil && alert.Deployment.Namespace != "" {
				namespaces[alert.Deployment.Namespace] = true
			}
			// Also check common entity info for resources
			if alert.CommonEntityInfo != nil && alert.CommonEntityInfo.Namespace != "" {
				namespaces[alert.CommonEntityInfo.Namespace] = true
			}
		}
		log.Printf("Found %d unique namespaces in alerts data", len(namespaces))
	}

	// Extract namespaces from deployments (NDJSON format)
	if len(deploymentsNDJSON) > 0 {
		deploymentCount := 0
		scanner := bufio.NewScanner(bytes.NewReader(deploymentsNDJSON))

		// Increase buffer size for large deployment data
		const maxScanTokenSize = 10 * 1024 * 1024 // 10MB
		buf := make([]byte, maxScanTokenSize)
		scanner.Buffer(buf, maxScanTokenSize)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var exportLine DeploymentExportLine
			if err := json.Unmarshal(line, &exportLine); err != nil {
				log.Printf("Warning: failed to parse deployment line: %v", err)
				continue
			}

			if exportLine.Result != nil && exportLine.Result.Deployment != nil && exportLine.Result.Deployment.Namespace != "" {
				namespaces[exportLine.Result.Deployment.Namespace] = true
				deploymentCount++
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to scan deployments NDJSON: %w", err)
		}
		log.Printf("Found %d additional unique namespaces in %d deployments", len(namespaces)-deploymentCount, deploymentCount)
	}

	log.Printf("Total %d unique namespaces needed", len(namespaces))

	// Fetch all existing namespaces in a single API call
	log.Printf("Fetching existing namespaces...")
	existingNsList, err := kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list existing namespaces: %w", err)
	}

	// Build set of existing namespaces
	existingNamespaces := make(map[string]bool)
	for _, ns := range existingNsList.Items {
		existingNamespaces[ns.Name] = true
	}
	log.Printf("Found %d existing namespaces", len(existingNamespaces))

	// Compute which namespaces need to be created
	namespacesToCreate := make([]string, 0)
	for ns := range namespaces {
		if !existingNamespaces[ns] {
			namespacesToCreate = append(namespacesToCreate, ns)
		}
	}

	log.Printf("Need to create %d namespaces", len(namespacesToCreate))

	// Create missing namespaces
	created := 0
	failed := 0
	for _, ns := range namespacesToCreate {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns,
				Labels: map[string]string{
					"created-by": "mock-central",
				},
			},
		}

		if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{}); err != nil {
			log.Printf("Error creating namespace %s: %v", ns, err)
			failed++
			continue
		}

		created++
	}

	existing := len(namespaces) - len(namespacesToCreate)
	log.Printf("Namespace creation complete: %d created, %d failed, %d already existing, %d total", created, failed, existing, len(namespaces))
	return nil
}
