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

// ClusterSecurityResultsSpec defines the desired state of ClusterSecurityResults
// NOTE: This is a read-only resource created by the operator.
// Spec is intentionally empty - all data is in Status.
type ClusterSecurityResultsSpec struct {
	// This resource is managed by the operator and has no user-configurable spec.
}

// NodeVulnerabilityData contains node vulnerability information
type NodeVulnerabilityData struct {
	// +kubebuilder:validation:Required
	NodeName string `json:"nodeName"`

	// +kubebuilder:validation:Required
	OSImage string `json:"osImage"`

	// +optional
	KernelVersion string `json:"kernelVersion,omitempty"`

	// +kubebuilder:validation:Required
	ScanTime metav1.Time `json:"scanTime"`

	// +kubebuilder:validation:Required
	Summary VulnerabilitySummary `json:"summary"`

	// Top CVEs (limited)
	// +optional
	// +kubebuilder:validation:MaxItems=50
	CVEs []CVE `json:"cves,omitempty"`
}

// ClusterSecurityResultsStatus defines the observed state of ClusterSecurityResults
// This contains all the cluster-wide security finding data from StackRox Central
type ClusterSecurityResultsStatus struct {
	// All node vulnerabilities in the cluster
	// +optional
	NodeVulnerabilities []NodeVulnerabilityData `json:"nodeVulnerabilities,omitempty"`

	// Summary counts across all nodes
	// +optional
	Summary *ClusterSecuritySummary `json:"summary,omitempty"`

	// Last update time
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// Conditions represent the current state of the ClusterSecurityResults
	//
	// Condition types:
	// - "DataTruncated": indicates if data was truncated to stay within limits
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClusterSecuritySummary provides cluster-wide statistics
type ClusterSecuritySummary struct {
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
	SchemeBuilder.Register(&ClusterSecurityResults{}, &ClusterSecurityResultsList{})
}
