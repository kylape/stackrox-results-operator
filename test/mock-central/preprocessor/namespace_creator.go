package preprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

// CreateNamespaces extracts namespaces from alerts data and creates them in Kubernetes
func CreateNamespaces(ctx context.Context, kubeClient kubernetes.Interface, alertsJSON []byte) error {
	// Parse alerts
	var data AlertData
	if err := json.Unmarshal(alertsJSON, &data); err != nil {
		return fmt.Errorf("failed to parse alerts JSON: %w", err)
	}

	// Extract unique namespaces
	namespaces := make(map[string]bool)
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

	// Create each namespace
	created := 0
	existing := 0
	for ns := range namespaces {
		// Check if namespace already exists
		_, err := kubeClient.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err == nil {
			log.Printf("Namespace already exists: %s", ns)
			existing++
			continue
		}

		if !errors.IsNotFound(err) {
			log.Printf("Error checking namespace %s: %v", ns, err)
			continue
		}

		// Create namespace
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
			continue
		}

		log.Printf("Created namespace: %s", ns)
		created++
	}

	log.Printf("Namespace creation complete: %d created, %d already existing, %d total", created, existing, len(namespaces))
	return nil
}
