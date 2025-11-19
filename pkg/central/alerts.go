package central

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"google.golang.org/protobuf/encoding/protojson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/kylape/stackrox-results-operator/api/security/v1alpha1"
)

// ListAlertsOptions contains options for listing alerts
type ListAlertsOptions struct {
	// Namespace filter
	Namespace string
	// Severity filter (LOW, MEDIUM, HIGH, CRITICAL)
	MinSeverity string
	// Lifecycle stages to include
	LifecycleStages []string
	// Exclude resolved alerts
	ExcludeResolved bool
	// Limit number of results
	Limit int
}

// ListAlerts fetches alerts from Central
func (c *Client) ListAlerts(ctx context.Context, opts ListAlertsOptions) ([]*storage.ListAlert, error) {
	log.V(1).Info("Listing alerts from Central", "namespace", opts.Namespace)

	// Build query parameters
	query := url.Values{}

	// Add filters
	filters := []string{}

	if opts.Namespace != "" {
		filters = append(filters, fmt.Sprintf("Namespace:%s", opts.Namespace))
	}

	if opts.MinSeverity != "" {
		severityLevels := getSeverityLevelsAbove(opts.MinSeverity)
		for _, sev := range severityLevels {
			filters = append(filters, fmt.Sprintf("Severity:%s", sev))
		}
	}

	if len(opts.LifecycleStages) > 0 {
		for _, stage := range opts.LifecycleStages {
			filters = append(filters, fmt.Sprintf("Lifecycle Stage:%s", stage))
		}
	}

	if opts.ExcludeResolved {
		filters = append(filters, "Violation State:ACTIVE")
	}

	if len(filters) > 0 {
		query.Set("query", strings.Join(filters, "+"))
	}

	if opts.Limit > 0 {
		query.Set("pagination.limit", fmt.Sprintf("%d", opts.Limit))
	}

	// Make request
	path := "/v1/alerts"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list alerts")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("list alerts failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	// Parse JSON response into a generic structure first
	var jsonResponse struct {
		Alerts []json.RawMessage `json:"alerts"`
	}

	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, errors.Wrap(err, "failed to parse alerts JSON response")
	}

	// Convert each alert using protojson
	alerts := make([]*storage.ListAlert, 0, len(jsonResponse.Alerts))
	for _, alertJSON := range jsonResponse.Alerts {
		alert := &storage.ListAlert{}
		if err := protojson.Unmarshal(alertJSON, alert); err != nil {
			return nil, errors.Wrap(err, "failed to parse alert protobuf")
		}
		alerts = append(alerts, alert)
	}

	log.Info("Retrieved alerts from Central", "count", len(alerts))
	return alerts, nil
}

// GetAlert fetches a single alert by ID
func (c *Client) GetAlert(ctx context.Context, alertID string) (*storage.Alert, error) {
	log.V(1).Info("Getting alert from Central", "alertID", alertID)

	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/v1/alerts/%s", alertID))
	if err != nil {
		return nil, errors.Wrap(err, "failed to get alert")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("get alert failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	alert := &storage.Alert{}
	if err := protojson.Unmarshal(body, alert); err != nil {
		return nil, errors.Wrap(err, "failed to parse alert response")
	}

	return alert, nil
}

// ConvertListAlertToCRD converts a storage.ListAlert to our Alert CRD format
func ConvertListAlertToCRD(a *storage.ListAlert, exporterName string) *securityv1alpha1.Alert {
	alert := &securityv1alpha1.Alert{
		Spec: securityv1alpha1.AlertSpec{},
		Status: securityv1alpha1.AlertStatus{
			PolicyID:       a.GetPolicy().GetId(),
			PolicyName:     a.GetPolicy().GetName(),
			PolicySeverity: NormalizeStorageSeverity(a.GetPolicy().GetSeverity()),
			LifecycleStage: a.GetLifecycleStage().String(),
		},
	}

	// Set metadata
	alert.Name = generateAlertNameFromListAlert(a)
	alert.Labels = map[string]string{
		"app.kubernetes.io/managed-by": "results-operator",
		"results.stackrox.io/exporter": exporterName,
		"stackrox.io/alert-id":         a.GetId(),
		"stackrox.io/policy-name":      sanitizeLabelValue(a.GetPolicy().GetName()),
		"stackrox.io/severity":         a.GetPolicy().GetSeverity().String(),
		"stackrox.io/lifecycle":        a.GetLifecycleStage().String(),
	}

	// Policy categories
	if len(a.GetPolicy().GetCategories()) > 0 {
		alert.Status.PolicyCategories = a.GetPolicy().GetCategories()
	}

	// Policy description
	if desc := a.GetPolicy().GetDescription(); desc != "" {
		alert.Status.PolicyDescription = desc
	}

	// Get common entity info first (has cluster/namespace/resource type)
	common := a.GetCommonEntityInfo()

	// Entity information from ListAlert
	if deployment := a.GetDeployment(); deployment != nil {
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type:        "DEPLOYMENT",
			ID:          deployment.GetId(),
			Name:        deployment.GetName(),
			Namespace:   deployment.GetNamespace(),
			ClusterID:   deployment.GetClusterId(),
			ClusterName: deployment.GetClusterName(),
		}
	} else if resource := a.GetResource(); resource != nil {
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Name: resource.GetName(),
		}
		// Get cluster/namespace/resource type from common entity info
		if common != nil {
			alert.Status.Entity.ResourceType = common.GetResourceType().String()
			alert.Status.Entity.Type = common.GetResourceType().String()
			alert.Status.Entity.Namespace = common.GetNamespace()
			alert.Status.Entity.ClusterID = common.GetClusterId()
			alert.Status.Entity.ClusterName = common.GetClusterName()
		}
	}

	// Timestamps
	if a.GetTime() != nil {
		alert.Status.Time = &metav1.Time{Time: a.GetTime().AsTime()}
	}

	// State and enforcement
	if a.GetState() != 0 {
		alert.Status.State = a.GetState().String()
		alert.Labels["stackrox.io/state"] = a.GetState().String()
	}

	if a.GetEnforcementAction() != 0 {
		alert.Status.EnforcementAction = a.GetEnforcementAction().String()
	}

	if a.GetEnforcementCount() > 0 {
		alert.Status.EnforcementCount = int(a.GetEnforcementCount())
	}

	return alert
}

// ConvertListAlertToClusterCRD converts a storage.ListAlert to a ClusterAlert CRD
func ConvertListAlertToClusterCRD(a *storage.ListAlert, exporterName string) *securityv1alpha1.ClusterAlert {
	alert := &securityv1alpha1.ClusterAlert{
		Spec: securityv1alpha1.ClusterAlertSpec{},
		Status: securityv1alpha1.ClusterAlertStatus{
			PolicyID:       a.GetPolicy().GetId(),
			PolicyName:     a.GetPolicy().GetName(),
			PolicySeverity: NormalizeStorageSeverity(a.GetPolicy().GetSeverity()),
			LifecycleStage: a.GetLifecycleStage().String(),
		},
	}

	// Set metadata
	alert.Name = generateAlertNameFromListAlert(a)
	alert.Labels = map[string]string{
		"app.kubernetes.io/managed-by": "results-operator",
		"results.stackrox.io/exporter": exporterName,
		"stackrox.io/alert-id":         a.GetId(),
		"stackrox.io/policy-name":      sanitizeLabelValue(a.GetPolicy().GetName()),
		"stackrox.io/severity":         a.GetPolicy().GetSeverity().String(),
		"stackrox.io/lifecycle":        a.GetLifecycleStage().String(),
	}

	// Policy categories
	if len(a.GetPolicy().GetCategories()) > 0 {
		alert.Status.PolicyCategories = a.GetPolicy().GetCategories()
	}

	// Policy description
	if desc := a.GetPolicy().GetDescription(); desc != "" {
		alert.Status.PolicyDescription = desc
	}

	// Get common entity info first (has cluster/namespace/resource type)
	common := a.GetCommonEntityInfo()

	// Entity information
	if deployment := a.GetDeployment(); deployment != nil {
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type:        "DEPLOYMENT",
			ID:          deployment.GetId(),
			Name:        deployment.GetName(),
			Namespace:   deployment.GetNamespace(),
			ClusterID:   deployment.GetClusterId(),
			ClusterName: deployment.GetClusterName(),
		}
	} else if resource := a.GetResource(); resource != nil {
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Name: resource.GetName(),
		}
		// Get cluster/namespace/resource type from common entity info
		if common != nil {
			alert.Status.Entity.ResourceType = common.GetResourceType().String()
			alert.Status.Entity.Type = common.GetResourceType().String()
			alert.Status.Entity.Namespace = common.GetNamespace()
			alert.Status.Entity.ClusterID = common.GetClusterId()
			alert.Status.Entity.ClusterName = common.GetClusterName()
		}
	}

	// Timestamps
	if a.GetTime() != nil {
		alert.Status.Time = &metav1.Time{Time: a.GetTime().AsTime()}
	}

	// State and enforcement
	if a.GetState() != 0 {
		alert.Status.State = a.GetState().String()
		alert.Labels["stackrox.io/state"] = a.GetState().String()
	}

	if a.GetEnforcementAction() != 0 {
		alert.Status.EnforcementAction = a.GetEnforcementAction().String()
	}

	if a.GetEnforcementCount() > 0 {
		alert.Status.EnforcementCount = int(a.GetEnforcementCount())
	}

	return alert
}

// Helper functions

// NormalizeStorageSeverity converts a storage.Severity to a string without the _SEVERITY suffix
func NormalizeStorageSeverity(severity storage.Severity) string {
	switch severity {
	case storage.Severity_CRITICAL_SEVERITY:
		return "CRITICAL"
	case storage.Severity_HIGH_SEVERITY:
		return "HIGH"
	case storage.Severity_MEDIUM_SEVERITY:
		return "MEDIUM"
	case storage.Severity_LOW_SEVERITY:
		return "LOW"
	default:
		return "LOW"
	}
}

func generateAlertNameFromListAlert(a *storage.ListAlert) string {
	// Generate a Kubernetes-friendly name from alert ID
	// Format: alert-<policy-name-prefix>-<short-id>
	policyPrefix := strings.ToLower(a.GetPolicy().GetName())
	policyPrefix = strings.ReplaceAll(policyPrefix, " ", "-")
	policyPrefix = strings.ReplaceAll(policyPrefix, "_", "-")

	// Limit policy prefix to 30 chars
	if len(policyPrefix) > 30 {
		policyPrefix = policyPrefix[:30]
	}

	// Use last 8 chars of ID
	shortID := a.GetId()
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}

	return fmt.Sprintf("alert-%s-%s", policyPrefix, shortID)
}

func sanitizeLabelValue(value string) string {
	// Kubernetes labels have restrictions
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, "@", "-")
	value = strings.ReplaceAll(value, "/", "-")
	// Note: "." is allowed in labels, so we keep it

	// Limit to 63 chars
	if len(value) > 63 {
		value = value[:63]
	}

	return value
}

func getSeverityLevelsAbove(minSeverity string) []string {
	severities := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	minLevel := severities[minSeverity]
	result := []string{}

	for sev, level := range severities {
		if level >= minLevel {
			result = append(result, sev)
		}
	}

	return result
}

// parseTime parses an RFC3339 timestamp string (kept for backward compatibility with vulnerabilities.go)
func parseTime(timeStr string) (*metav1.Time, error) {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, err
	}
	return &metav1.Time{Time: t}, nil
}
