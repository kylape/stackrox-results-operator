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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/kylape/stackrox-results-operator/api/security/v1alpha1"
)

// Alert represents an alert from Central API
// This is the API response format, which we'll convert to our CRD format
// Note: The list endpoint (/v1/alerts) returns deployment/namespace at the top level,
// while the detail endpoint (/v1/alerts/{id}) returns them in an "entity" field.
// We support both formats.
type Alert struct {
	ID                string       `json:"id"`
	Policy            *Policy      `json:"policy"`
	LifecycleStage    string       `json:"lifecycleStage"`

	// Fields from list endpoint (/v1/alerts)
	Deployment       *DeploymentInfo    `json:"deployment,omitempty"`
	Namespace        string             `json:"namespace,omitempty"`
	CommonEntityInfo *CommonEntityInfo  `json:"commonEntityInfo,omitempty"`

	// Fields from detail endpoint (/v1/alerts/{id})
	Entity            *AlertEntity `json:"entity,omitempty"`
	Violations        []*Violation `json:"violations,omitempty"`

	// Common fields
	Time              string       `json:"time"`
	FirstOccurred     string       `json:"firstOccurred,omitempty"`
	State             string       `json:"state,omitempty"`
	ResolvedAt        string       `json:"resolvedAt,omitempty"`
	EnforcementAction string       `json:"enforcementAction,omitempty"`
	EnforcementCount  int          `json:"enforcementCount,omitempty"`
}

type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Categories  []string `json:"categories,omitempty"`
	Description string   `json:"description,omitempty"`
}

type AlertEntity struct {
	Type       string          `json:"type,omitempty"`
	Deployment *DeploymentInfo `json:"deployment,omitempty"`
	Image      *ImageInfo      `json:"image,omitempty"`
	Resource   *ResourceInfo   `json:"resource,omitempty"`
}

type DeploymentInfo struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	ClusterID   string `json:"clusterId,omitempty"`
	ClusterName string `json:"clusterName,omitempty"`
}

type ImageInfo struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ResourceInfo struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

type CommonEntityInfo struct {
	Namespace    string `json:"namespace,omitempty"`
	ResourceType string `json:"resourceType,omitempty"`
}

type Violation struct {
	Message       string          `json:"message,omitempty"`
	Type          string          `json:"type,omitempty"`
	KeyValueAttrs []*KeyValueAttr `json:"keyValueAttrs,omitempty"`
}

type KeyValueAttr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

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
func (c *Client) ListAlerts(ctx context.Context, opts ListAlertsOptions) ([]*Alert, error) {
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

	var response struct {
		Alerts []*Alert `json:"alerts"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.Wrap(err, "failed to parse alerts response")
	}

	log.Info("Retrieved alerts from Central", "count", len(response.Alerts))
	return response.Alerts, nil
}

// GetAlert fetches a single alert by ID
func (c *Client) GetAlert(ctx context.Context, alertID string) (*Alert, error) {
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

	var alert Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		return nil, errors.Wrap(err, "failed to parse alert response")
	}

	return &alert, nil
}

// ConvertToCRD converts a Central API alert to our Alert CRD format
func (a *Alert) ConvertToCRD() *securityv1alpha1.Alert {
	alert := &securityv1alpha1.Alert{
		Spec: securityv1alpha1.AlertSpec{},
		Status: securityv1alpha1.AlertStatus{
			PolicyID:       a.Policy.ID,
			PolicyName:     a.Policy.Name,
			PolicySeverity: normalizeAlertSeverity(a.Policy.Severity),
			LifecycleStage: a.LifecycleStage,
		},
	}

	// Set metadata
	alert.Name = generateAlertName(a)
	alert.Labels = map[string]string{
		"stackrox.io/alert-id":    a.ID,
		"stackrox.io/policy-name": sanitizeLabelValue(a.Policy.Name),
		"stackrox.io/severity":    a.Policy.Severity,
		"stackrox.io/lifecycle":   a.LifecycleStage,
	}

	// Policy categories
	if len(a.Policy.Categories) > 0 {
		alert.Status.PolicyCategories = a.Policy.Categories
	}

	// Policy description
	if a.Policy.Description != "" {
		alert.Status.PolicyDescription = a.Policy.Description
	}

	// Entity information
	// The list endpoint (/v1/alerts) returns deployment at the top level,
	// while the detail endpoint (/v1/alerts/{id}) returns it in an entity field.
	// We check both formats.
	if a.Deployment != nil {
		// List endpoint format
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type: "DEPLOYMENT",
			Deployment: &securityv1alpha1.DeploymentInfo{
				ID:          a.Deployment.ID,
				Name:        a.Deployment.Name,
				Namespace:   a.Deployment.Namespace,
				ClusterID:   a.Deployment.ClusterID,
				ClusterName: a.Deployment.ClusterName,
			},
		}
	} else if a.Entity != nil {
		// Detail endpoint format
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type: a.Entity.Type,
		}

		if a.Entity.Deployment != nil {
			alert.Status.Entity.Deployment = &securityv1alpha1.DeploymentInfo{
				ID:          a.Entity.Deployment.ID,
				Name:        a.Entity.Deployment.Name,
				Namespace:   a.Entity.Deployment.Namespace,
				ClusterID:   a.Entity.Deployment.ClusterID,
				ClusterName: a.Entity.Deployment.ClusterName,
			}
		}

		if a.Entity.Image != nil {
			alert.Status.Entity.Image = &securityv1alpha1.ImageInfo{
				ID:   a.Entity.Image.ID,
				Name: a.Entity.Image.Name,
			}
		}

		if a.Entity.Resource != nil {
			alert.Status.Entity.Resource = &securityv1alpha1.ResourceInfo{
				Type: a.Entity.Resource.Type,
				Name: a.Entity.Resource.Name,
			}
		}
	}

	// Violations
	if len(a.Violations) > 0 {
		alert.Status.Violations = make([]securityv1alpha1.Violation, len(a.Violations))
		for i, v := range a.Violations {
			violation := securityv1alpha1.Violation{
				Message: v.Message,
				Type:    v.Type,
			}

			if len(v.KeyValueAttrs) > 0 {
				violation.KeyValueAttrs = make([]securityv1alpha1.KeyValueAttr, len(v.KeyValueAttrs))
				for j, kv := range v.KeyValueAttrs {
					violation.KeyValueAttrs[j] = securityv1alpha1.KeyValueAttr{
						Key:   kv.Key,
						Value: kv.Value,
					}
				}
			}

			alert.Status.Violations[i] = violation
		}
	}

	// Timestamps
	if timeVal, err := parseTime(a.Time); err == nil {
		alert.Status.Time = timeVal
	}

	if a.FirstOccurred != "" {
		if timeVal, err := parseTime(a.FirstOccurred); err == nil {
			alert.Status.FirstOccurred = timeVal
		}
	}

	// State and enforcement
	if a.State != "" {
		alert.Status.State = a.State
		alert.Labels["stackrox.io/state"] = a.State
	}

	if a.ResolvedAt != "" {
		if timeVal, err := parseTime(a.ResolvedAt); err == nil {
			alert.Status.ResolvedAt = timeVal
		}
	}

	if a.EnforcementAction != "" {
		alert.Status.EnforcementAction = a.EnforcementAction
	}

	if a.EnforcementCount > 0 {
		alert.Status.EnforcementCount = a.EnforcementCount
	}

	return alert
}

// ConvertToClusterCRD converts a StackRox Alert to a ClusterAlert CRD
// This is used for cluster-scoped alerts (alerts without a namespace)
func (a *Alert) ConvertToClusterCRD() *securityv1alpha1.ClusterAlert {
	alert := &securityv1alpha1.ClusterAlert{
		Spec: securityv1alpha1.ClusterAlertSpec{},
		Status: securityv1alpha1.ClusterAlertStatus{
			PolicyID:       a.Policy.ID,
			PolicyName:     a.Policy.Name,
			PolicySeverity: normalizeAlertSeverity(a.Policy.Severity),
			LifecycleStage: a.LifecycleStage,
		},
	}

	// Set metadata
	alert.Name = generateAlertName(a)
	alert.Labels = map[string]string{
		"stackrox.io/alert-id":    a.ID,
		"stackrox.io/policy-name": sanitizeLabelValue(a.Policy.Name),
		"stackrox.io/severity":    a.Policy.Severity,
		"stackrox.io/lifecycle":   a.LifecycleStage,
	}

	// Policy categories
	if len(a.Policy.Categories) > 0 {
		alert.Status.PolicyCategories = a.Policy.Categories
	}

	// Policy description
	if a.Policy.Description != "" {
		alert.Status.PolicyDescription = a.Policy.Description
	}

	// Entity information
	// The list endpoint (/v1/alerts) returns deployment at the top level,
	// while the detail endpoint (/v1/alerts/{id}) returns it in an entity field.
	// We check both formats.
	if a.Deployment != nil {
		// List endpoint format
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type: "DEPLOYMENT",
			Deployment: &securityv1alpha1.DeploymentInfo{
				ID:          a.Deployment.ID,
				Name:        a.Deployment.Name,
				Namespace:   a.Deployment.Namespace,
				ClusterID:   a.Deployment.ClusterID,
				ClusterName: a.Deployment.ClusterName,
			},
		}
	} else if a.Entity != nil {
		// Detail endpoint format
		alert.Status.Entity = &securityv1alpha1.AlertEntity{
			Type: a.Entity.Type,
		}

		if a.Entity.Deployment != nil {
			alert.Status.Entity.Deployment = &securityv1alpha1.DeploymentInfo{
				ID:          a.Entity.Deployment.ID,
				Name:        a.Entity.Deployment.Name,
				Namespace:   a.Entity.Deployment.Namespace,
				ClusterID:   a.Entity.Deployment.ClusterID,
				ClusterName: a.Entity.Deployment.ClusterName,
			}
		}

		if a.Entity.Image != nil {
			alert.Status.Entity.Image = &securityv1alpha1.ImageInfo{
				ID:   a.Entity.Image.ID,
				Name: a.Entity.Image.Name,
			}
		}

		if a.Entity.Resource != nil {
			alert.Status.Entity.Resource = &securityv1alpha1.ResourceInfo{
				Type: a.Entity.Resource.Type,
				Name: a.Entity.Resource.Name,
			}
		}
	}

	// Violations
	if len(a.Violations) > 0 {
		alert.Status.Violations = make([]securityv1alpha1.Violation, len(a.Violations))
		for i, v := range a.Violations {
			violation := securityv1alpha1.Violation{
				Message: v.Message,
				Type:    v.Type,
			}

			if len(v.KeyValueAttrs) > 0 {
				violation.KeyValueAttrs = make([]securityv1alpha1.KeyValueAttr, len(v.KeyValueAttrs))
				for j, kv := range v.KeyValueAttrs {
					violation.KeyValueAttrs[j] = securityv1alpha1.KeyValueAttr{
						Key:   kv.Key,
						Value: kv.Value,
					}
				}
			}

			alert.Status.Violations[i] = violation
		}
	}

	// Timestamps
	if timeVal, err := parseTime(a.Time); err == nil {
		alert.Status.Time = timeVal
	}

	if a.FirstOccurred != "" {
		if timeVal, err := parseTime(a.FirstOccurred); err == nil {
			alert.Status.FirstOccurred = timeVal
		}
	}

	// State and enforcement
	if a.State != "" {
		alert.Status.State = a.State
		alert.Labels["stackrox.io/state"] = a.State
	}

	if a.ResolvedAt != "" {
		if timeVal, err := parseTime(a.ResolvedAt); err == nil {
			alert.Status.ResolvedAt = timeVal
		}
	}

	if a.EnforcementAction != "" {
		alert.Status.EnforcementAction = a.EnforcementAction
	}

	if a.EnforcementCount > 0 {
		alert.Status.EnforcementCount = a.EnforcementCount
	}

	return alert
}

// Helper functions

func normalizeAlertSeverity(severity string) string {
	// Normalize StackRox alert severity values to CRD-expected values
	severity = strings.ToUpper(severity)
	switch severity {
	case "CRITICAL", "CRITICAL_SEVERITY":
		return "CRITICAL"
	case "HIGH", "HIGH_SEVERITY":
		return "HIGH"
	case "MEDIUM", "MEDIUM_SEVERITY":
		return "MEDIUM"
	case "LOW", "LOW_SEVERITY":
		return "LOW"
	default:
		return "LOW" // Default to LOW for unknown severities
	}
}

func generateAlertName(a *Alert) string {
	// Generate a Kubernetes-friendly name from alert ID
	// Format: alert-<policy-name-prefix>-<short-id>
	policyPrefix := strings.ToLower(a.Policy.Name)
	policyPrefix = strings.ReplaceAll(policyPrefix, " ", "-")
	policyPrefix = strings.ReplaceAll(policyPrefix, "_", "-")

	// Limit policy prefix to 30 chars
	if len(policyPrefix) > 30 {
		policyPrefix = policyPrefix[:30]
	}

	// Use last 8 chars of ID
	shortID := a.ID
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

func parseTime(timeStr string) (*metav1.Time, error) {
	// Parse RFC3339 format
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, err
	}
	return &metav1.Time{Time: t}, nil
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
