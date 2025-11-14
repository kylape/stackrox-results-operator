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

// Common types shared across SecurityResults and ClusterSecurityResults

// CVE describes a vulnerability
type CVE struct {
	// CVE identifier
	// +kubebuilder:validation:Pattern:=`^CVE-[0-9]{4}-[0-9]+$`
	// +kubebuilder:validation:Required
	CVE string `json:"cve"`

	// Severity level
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum:=CRITICAL;HIGH;MEDIUM;LOW
	Severity string `json:"severity"`

	// CVSS score (0-10)
	// +optional
	CVSS string `json:"cvss,omitempty"`

	// CVSSv3 scoring
	// +optional
	CVSSv3 *CVSSv3 `json:"cvssV3,omitempty"`

	// Link to CVE details
	// +optional
	Link string `json:"link,omitempty"`

	// Short description of the vulnerability
	// +optional
	Summary string `json:"summary,omitempty"`

	// Version that fixes this CVE
	// +optional
	FixedBy string `json:"fixedBy,omitempty"`

	// Vulnerable component
	// +optional
	Component *Component `json:"component,omitempty"`

	// Exploit Prediction Scoring System data
	// +optional
	EPSS *EPSS `json:"epss,omitempty"`

	// When the CVE was published
	// +optional
	Published *metav1.Time `json:"published,omitempty"`

	// When the CVE was discovered in the image
	// +optional
	DiscoveredInImage *metav1.Time `json:"discoveredInImage,omitempty"`

	// Current state of the CVE
	// +optional
	// +kubebuilder:validation:Enum:=OBSERVED;DEFERRED;FALSE_POSITIVE
	State string `json:"state,omitempty"`

	// Whether this CVE is fixable
	// +optional
	Fixable bool `json:"fixable,omitempty"`
}

// CVSSv3 contains CVSS v3 scoring
type CVSSv3 struct {
	// CVSS v3 score
	// +kubebuilder:validation:Required
	Score string `json:"score"`

	// CVSS v3 vector
	// +kubebuilder:validation:Required
	Vector string `json:"vector"`
}

// Component describes a vulnerable software component
type Component struct {
	// Component name
	// +optional
	Name string `json:"name,omitempty"`

	// Component version
	// +optional
	Version string `json:"version,omitempty"`

	// Component location in the image
	// +optional
	Location string `json:"location,omitempty"`
}

// EPSS contains Exploit Prediction Scoring System data
type EPSS struct {
	// EPSS score (0-1)
	// +kubebuilder:validation:Required
	Score string `json:"score"`

	// EPSS percentile (0-1)
	// +kubebuilder:validation:Required
	Percentile string `json:"percentile"`
}

// SeverityCount counts vulnerabilities at a severity level
type SeverityCount struct {
	// Total vulnerabilities at this severity
	// +kubebuilder:validation:Required
	Total int `json:"total"`

	// Fixable vulnerabilities at this severity
	// +kubebuilder:validation:Required
	Fixable int `json:"fixable"`
}

// VulnerabilitySummary summarizes vulnerabilities by severity
type VulnerabilitySummary struct {
	// Total number of vulnerabilities
	// +kubebuilder:validation:Required
	Total int `json:"total"`

	// Total number of fixable vulnerabilities
	// +kubebuilder:validation:Required
	FixableTotal int `json:"fixableTotal"`

	// Critical severity vulnerabilities
	// +optional
	Critical *SeverityCount `json:"critical,omitempty"`

	// High severity vulnerabilities
	// +optional
	High *SeverityCount `json:"high,omitempty"`

	// Medium severity vulnerabilities
	// +optional
	Medium *SeverityCount `json:"medium,omitempty"`

	// Low severity vulnerabilities
	// +optional
	Low *SeverityCount `json:"low,omitempty"`
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
	// +kubebuilder:validation:Enum:=CRITICAL;HIGH;MEDIUM;LOW
	PolicySeverity string `json:"policySeverity"`

	// +optional
	PolicyCategories []string `json:"policyCategories,omitempty"`

	// Lifecycle stage
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum:=DEPLOY;RUNTIME
	LifecycleStage string `json:"lifecycleStage"`

	// Entity that violated the policy
	// +optional
	Entity *AlertEntity `json:"entity,omitempty"`

	// Specific violations
	// +optional
	Violations []Violation `json:"violations,omitempty"`

	// When this alert occurred
	// +kubebuilder:validation:Required
	Time metav1.Time `json:"time"`

	// When this alert was first triggered
	// +optional
	FirstOccurred *metav1.Time `json:"firstOccurred,omitempty"`

	// Current state
	// +optional
	// +kubebuilder:validation:Enum:=ACTIVE;RESOLVED;ATTEMPTED
	State string `json:"state,omitempty"`

	// When the alert was resolved
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`
}

// AlertEntity describes the Kubernetes entity that violated the policy
type AlertEntity struct {
	// Type of entity (Deployment, Pod, Image, Node, Resource)
	// +optional
	Type string `json:"type,omitempty"`

	// Entity ID
	// +optional
	ID string `json:"id,omitempty"`

	// Entity name (deployment name, image name, resource name, etc.)
	// +optional
	Name string `json:"name,omitempty"`

	// Namespace (for namespaced entities)
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Cluster name
	// +optional
	ClusterName string `json:"clusterName,omitempty"`

	// Cluster ID
	// +optional
	ClusterID string `json:"clusterId,omitempty"`

	// Resource type (for Resource entities - e.g., "Secret", "ConfigMap")
	// +optional
	ResourceType string `json:"resourceType,omitempty"`
}

// Violation describes a specific policy violation
type Violation struct {
	// Human-readable violation message
	// +optional
	Message string `json:"message,omitempty"`

	// Type of violation
	// +optional
	Type string `json:"type,omitempty"`

	// Additional violation attributes
	// +optional
	KeyValueAttrs []KeyValueAttr `json:"keyValueAttrs,omitempty"`
}

// KeyValueAttr is a key-value pair for violation details
type KeyValueAttr struct {
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

// ImageVulnerabilityData contains image vulnerability information
type ImageVulnerabilityData struct {
	// Image reference
	// +kubebuilder:validation:Required
	Image ImageReference `json:"image"`

	// When the image was scanned
	// +kubebuilder:validation:Required
	ScanTime metav1.Time `json:"scanTime"`

	// Vulnerability summary
	// +kubebuilder:validation:Required
	Summary VulnerabilitySummary `json:"summary"`

	// Top CVEs (limited)
	// +optional
	// +kubebuilder:validation:MaxItems:=50
	CVEs []CVE `json:"cves,omitempty"`
}

// ImageReference describes a container image
type ImageReference struct {
	// Image name
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Image SHA digest
	// +kubebuilder:validation:Required
	SHA string `json:"sha"`

	// Registry hosting the image
	// +optional
	Registry string `json:"registry,omitempty"`

	// Remote path in registry
	// +optional
	Remote string `json:"remote,omitempty"`

	// Image tag
	// +optional
	Tag string `json:"tag,omitempty"`

	// Complete image reference
	// +optional
	FullName string `json:"fullName,omitempty"`
}

// NodeVulnerabilityData contains node vulnerability information
type NodeVulnerabilityData struct {
	// Name of the node
	// +kubebuilder:validation:Required
	NodeName string `json:"nodeName"`

	// Operating system image
	// +kubebuilder:validation:Required
	OSImage string `json:"osImage"`

	// Kernel version
	// +optional
	KernelVersion string `json:"kernelVersion,omitempty"`

	// When the node was scanned
	// +kubebuilder:validation:Required
	ScanTime metav1.Time `json:"scanTime"`

	// Vulnerability summary
	// +kubebuilder:validation:Required
	Summary VulnerabilitySummary `json:"summary"`

	// Top CVEs (limited)
	// +optional
	// +kubebuilder:validation:MaxItems:=50
	CVEs []CVE `json:"cves,omitempty"`
}

// SecurityResultsSpec defines the desired state of SecurityResults
// This is an aggregated view of all security findings in a namespace
type SecurityResultsSpec struct {
	// Namespace this result applies to
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// All alerts in this namespace
	// +optional
	Alerts []AlertData `json:"alerts,omitempty"`

	// All image vulnerabilities for images used in this namespace
	// +optional
	ImageVulnerabilities []ImageVulnerabilityData `json:"imageVulnerabilities,omitempty"`
}

// SecurityResultsStatus defines the observed state of SecurityResults
type SecurityResultsStatus struct {
	// Summary counts
	// +optional
	Summary *SecurityResultsSummary `json:"summary,omitempty"`

	// Last update time
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// SecurityResultsSummary contains summary counts for SecurityResults
type SecurityResultsSummary struct {
	// Alert counts by severity
	// +optional
	TotalAlerts int `json:"totalAlerts,omitempty"`

	// +optional
	CriticalAlerts int `json:"criticalAlerts,omitempty"`

	// +optional
	HighAlerts int `json:"highAlerts,omitempty"`

	// CVE counts across all images
	// +optional
	TotalCVEs int `json:"totalCVEs,omitempty"`

	// +optional
	CriticalCVEs int `json:"criticalCVEs,omitempty"`

	// +optional
	HighCVEs int `json:"highCVEs,omitempty"`

	// +optional
	FixableCVEs int `json:"fixableCVEs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=securityresults,scope=Namespaced
// +kubebuilder:printcolumn:name="Critical Alerts",type=integer,JSONPath=`.status.summary.criticalAlerts`
// +kubebuilder:printcolumn:name="High Alerts",type=integer,JSONPath=`.status.summary.highAlerts`
// +kubebuilder:printcolumn:name="Total Alerts",type=integer,JSONPath=`.status.summary.totalAlerts`
// +kubebuilder:printcolumn:name="Critical CVEs",type=integer,JSONPath=`.status.summary.criticalCVEs`
// +kubebuilder:printcolumn:name="Total CVEs",type=integer,JSONPath=`.status.summary.totalCVEs`
// +kubebuilder:printcolumn:name="Last Updated",type=date,JSONPath=`.status.lastUpdated`

// SecurityResults is the Schema for the securityresults API
// This aggregates all security findings for a namespace into a single resource
type SecurityResults struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityResultsSpec   `json:"spec,omitempty"`
	Status SecurityResultsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecurityResultsList contains a list of SecurityResults
type SecurityResultsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityResults `json:"items"`
}

// ClusterSecurityResultsSpec defines the desired state of ClusterSecurityResults
// This aggregates cluster-wide security findings (node vulnerabilities)
type ClusterSecurityResultsSpec struct {
	// All node vulnerabilities in the cluster
	// +optional
	NodeVulnerabilities []NodeVulnerabilityData `json:"nodeVulnerabilities,omitempty"`
}

// ClusterSecurityResultsStatus defines the observed state of ClusterSecurityResults
type ClusterSecurityResultsStatus struct {
	// Summary counts across all nodes
	// +optional
	Summary *ClusterSecurityResultsSummary `json:"summary,omitempty"`

	// Last update time
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`
}

// ClusterSecurityResultsSummary contains summary counts for ClusterSecurityResults
type ClusterSecurityResultsSummary struct {
	// Number of nodes scanned
	// +optional
	NodesScanned int `json:"nodesScanned,omitempty"`

	// Nodes with critical vulnerabilities
	// +optional
	NodesWithCritical int `json:"nodesWithCritical,omitempty"`

	// Nodes with high vulnerabilities
	// +optional
	NodesWithHigh int `json:"nodesWithHigh,omitempty"`

	// Total CVEs across all nodes
	// +optional
	TotalCVEs int `json:"totalCVEs,omitempty"`

	// Fixable CVEs across all nodes
	// +optional
	FixableCVEs int `json:"fixableCVEs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=clustersecurityresults,scope=Cluster
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.summary.nodesScanned`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.status.summary.nodesWithCritical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.status.summary.nodesWithHigh`
// +kubebuilder:printcolumn:name="Total CVEs",type=integer,JSONPath=`.status.summary.totalCVEs`
// +kubebuilder:printcolumn:name="Fixable",type=integer,JSONPath=`.status.summary.fixableCVEs`
// +kubebuilder:printcolumn:name="Last Updated",type=date,JSONPath=`.status.lastUpdated`

// ClusterSecurityResults is the Schema for the clustersecurityresults API
// This aggregates all cluster-wide security findings into a single resource
type ClusterSecurityResults struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSecurityResultsSpec   `json:"spec,omitempty"`
	Status ClusterSecurityResultsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterSecurityResultsList contains a list of ClusterSecurityResults
type ClusterSecurityResultsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterSecurityResults `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityResults{}, &SecurityResultsList{})
	SchemeBuilder.Register(&ClusterSecurityResults{}, &ClusterSecurityResultsList{})
}
