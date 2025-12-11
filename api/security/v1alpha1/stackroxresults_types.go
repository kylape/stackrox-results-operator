/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StackRoxResultsSpec defines the desired state of StackRoxResults
// NOTE: This is a read-only resource created by the operator.
// Spec is intentionally empty - all data is in Status.
type StackRoxResultsSpec struct {
	// This resource is managed by the operator and has no user-configurable spec.
}

// AlertData contains the same information as Alert.Spec
type AlertData struct {
	// Alert ID from Central
	// +kubebuilder:validation:Required
	ID string `json:"id"`

	// Policy information
	// +kubebuilder:validation:Required
	PolicyID string `json:"policyId"`

	// +kubebuilder:validation:Required
	PolicyName string `json:"policyName"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW;UNKNOWN
	PolicySeverity string `json:"policySeverity"`

	// +optional
	PolicyCategories []string `json:"policyCategories,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=DEPLOY;RUNTIME
	LifecycleStage string `json:"lifecycleStage"`

	// +optional
	Entity *AlertEntity `json:"entity,omitempty"`

	// +optional
	Violations []Violation `json:"violations,omitempty"`

	// +kubebuilder:validation:Required
	Time metav1.Time `json:"time"`

	// +optional
	FirstOccurred *metav1.Time `json:"firstOccurred,omitempty"`

	// Current state
	// +optional
	// +kubebuilder:validation:Enum=ACTIVE;RESOLVED;ATTEMPTED
	State string `json:"state,omitempty"`

	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`
}

// ImageVulnerabilityData contains image vulnerability information
type ImageVulnerabilityData struct {
	// Image reference
	// +kubebuilder:validation:Required
	Image ImageReference `json:"image"`

	// +kubebuilder:validation:Required
	ScanTime metav1.Time `json:"scanTime"`

	// +kubebuilder:validation:Required
	Summary VulnerabilitySummary `json:"summary"`

	// Top CVEs (limited)
	// +optional
	// +kubebuilder:validation:MaxItems=50
	CVEs []CVE `json:"cves,omitempty"`

	// Scan notes from Central (e.g., OS_UNAVAILABLE, PARTIAL_SCAN_DATA)
	// +optional
	Notes []string `json:"notes,omitempty"`
}

// StackRoxResultsStatus defines the observed state of StackRoxResults
// This contains all the security finding data from StackRox Central
type StackRoxResultsStatus struct {
	// All alerts in this namespace
	// +optional
	Alerts []AlertData `json:"alerts,omitempty"`

	// All image vulnerabilities for images used in this namespace
	// +optional
	ImageVulnerabilities []ImageVulnerabilityData `json:"imageVulnerabilities,omitempty"`

	// Summary counts
	// +optional
	Summary *SecuritySummary `json:"summary,omitempty"`

	// Last update time
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// Conditions represent the current state of the StackRoxResults
	//
	// Condition types:
	// - "DataTruncated": indicates if data was truncated to stay within limits
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SecuritySummary provides aggregate statistics
type SecuritySummary struct {
	// Alert counts by severity
	// +optional
	CriticalAlerts int `json:"criticalAlerts,omitempty"`

	// +optional
	HighAlerts int `json:"highAlerts,omitempty"`

	// +optional
	TotalAlerts int `json:"totalAlerts,omitempty"`

	// CVE counts across all images
	// +optional
	CriticalCVEs int `json:"criticalCVEs,omitempty"`

	// +optional
	HighCVEs int `json:"highCVEs,omitempty"`

	// +optional
	TotalCVEs int `json:"totalCVEs,omitempty"`

	// +optional
	FixableCVEs int `json:"fixableCVEs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=stackroxresults,scope=Namespaced
// +kubebuilder:printcolumn:name="Critical Alerts",type=integer,JSONPath=`.status.summary.criticalAlerts`
// +kubebuilder:printcolumn:name="High Alerts",type=integer,JSONPath=`.status.summary.highAlerts`
// +kubebuilder:printcolumn:name="Total Alerts",type=integer,JSONPath=`.status.summary.totalAlerts`
// +kubebuilder:printcolumn:name="Critical CVEs",type=integer,JSONPath=`.status.summary.criticalCVEs`
// +kubebuilder:printcolumn:name="Total CVEs",type=integer,JSONPath=`.status.summary.totalCVEs`
// +kubebuilder:printcolumn:name="Last Updated",type=date,JSONPath=`.status.lastUpdated`

// StackRoxResults is the Schema for the stackroxresults API
// This aggregates all security findings for a namespace into a single resource
type StackRoxResults struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StackRoxResultsSpec   `json:"spec,omitempty"`
	Status StackRoxResultsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// StackRoxResultsList contains a list of StackRoxResults
type StackRoxResultsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []StackRoxResults `json:"items"`
}

func init() {
	SchemeBuilder.Register(&StackRoxResults{}, &StackRoxResultsList{})
}
