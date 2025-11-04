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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ResultsExporterSpec defines the desired state of ResultsExporter
type ResultsExporterSpec struct {
	// Central connection configuration
	// +kubebuilder:validation:Required
	Central CentralConfig `json:"central"`

	// What to export
	// +kubebuilder:validation:Required
	Exports ExportConfig `json:"exports"`

	// How often to sync (default: 5m)
	// +kubebuilder:default:="5m"
	// +optional
	SyncInterval *metav1.Duration `json:"syncInterval,omitempty"`

	// How far back to backfill on initial sync (default: 720h = 30 days)
	// +kubebuilder:default:="720h"
	// +optional
	BackfillDuration *metav1.Duration `json:"backfillDuration,omitempty"`
}

// CentralConfig defines the connection to StackRox Central
type CentralConfig struct {
	// Central API endpoint
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern:=`^https?://.*`
	Endpoint string `json:"endpoint"`

	// Secret containing auth credentials (htpasswd or API token)
	// +kubebuilder:validation:Required
	AuthSecretName string `json:"authSecretName"`

	// TLS configuration
	// +optional
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	// Skip TLS verification (not recommended for production)
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// Secret containing CA bundle
	// +optional
	CABundleSecretName string `json:"caBundleSecretName,omitempty"`
}

// ExportConfig defines what to export
type ExportConfig struct {
	// Export alerts
	// +optional
	Alerts *AlertExportConfig `json:"alerts,omitempty"`

	// Export image vulnerabilities
	// +optional
	ImageVulnerabilities *ImageVulnExportConfig `json:"imageVulnerabilities,omitempty"`

	// Export node vulnerabilities
	// +optional
	NodeVulnerabilities *NodeVulnExportConfig `json:"nodeVulnerabilities,omitempty"`
}

// AlertExportConfig defines alert export settings
type AlertExportConfig struct {
	// Enable alert export
	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	// Filters
	// +optional
	Filters *AlertFilters `json:"filters,omitempty"`

	// Max alerts per namespace (default: 1000)
	// +kubebuilder:default:=1000
	// +optional
	MaxPerNamespace int `json:"maxPerNamespace,omitempty"`
}

// AlertFilters defines filtering for alerts
type AlertFilters struct {
	// Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
	// +kubebuilder:validation:Enum:=LOW;MEDIUM;HIGH;CRITICAL
	// +optional
	MinSeverity string `json:"minSeverity,omitempty"`

	// Lifecycle stages to include
	// +optional
	LifecycleStages []string `json:"lifecycleStages,omitempty"`

	// Exclude resolved alerts
	// +optional
	ExcludeResolved bool `json:"excludeResolved,omitempty"`
}

// ImageVulnExportConfig defines image vulnerability export settings
type ImageVulnExportConfig struct {
	// Enable image vulnerability export
	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	// Filters
	// +optional
	Filters *VulnFilters `json:"filters,omitempty"`

	// Max images to export (default: 5000)
	// +kubebuilder:default:=5000
	// +optional
	MaxImages int `json:"maxImages,omitempty"`
}

// NodeVulnExportConfig defines node vulnerability export settings
type NodeVulnExportConfig struct {
	// Enable node vulnerability export
	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	// Filters
	// +optional
	Filters *VulnFilters `json:"filters,omitempty"`
}

// VulnFilters defines filtering for vulnerabilities
type VulnFilters struct {
	// Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
	// +kubebuilder:validation:Enum:=LOW;MEDIUM;HIGH;CRITICAL
	// +optional
	MinSeverity string `json:"minSeverity,omitempty"`

	// Only include fixable vulnerabilities
	// +optional
	FixableOnly bool `json:"fixableOnly,omitempty"`

	// Max CVEs per image/node (default: 50)
	// +kubebuilder:default:=50
	// +optional
	MaxCVEsPerResource int `json:"maxCVEsPerResource,omitempty"`
}

// ResultsExporterStatus defines the observed state of ResultsExporter.
type ResultsExporterStatus struct {
	// Conditions represent the current state of the ResultsExporter
	//
	// Standard condition types:
	// - "Ready": the exporter is functioning correctly
	// - "CentralConnected": connection to Central is established
	// - "Syncing": sync operation is in progress
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Last sync time
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Last successful sync
	// +optional
	LastSuccessfulSync *metav1.Time `json:"lastSuccessfulSync,omitempty"`

	// Sync duration
	// +optional
	SyncDuration *metav1.Duration `json:"syncDuration,omitempty"`

	// Exported resource counts
	// +optional
	ExportedResources *ExportedResourceCounts `json:"exportedResources,omitempty"`

	// Last sync error (if any)
	// +optional
	LastSyncError string `json:"lastSyncError,omitempty"`

	// Consecutive failures
	// +optional
	ConsecutiveFailures int `json:"consecutiveFailures,omitempty"`

	// Observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ExportedResourceCounts tracks how many resources have been exported
type ExportedResourceCounts struct {
	Alerts                 int `json:"alerts"`
	ImageVulnerabilities   int `json:"imageVulnerabilities"`
	NodeVulnerabilities    int `json:"nodeVulnerabilities"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=resultsexporters,scope=Namespaced
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Central",type=string,JSONPath=`.status.conditions[?(@.type=="CentralConnected")].status`
// +kubebuilder:printcolumn:name="Alerts",type=integer,JSONPath=`.status.exportedResources.alerts`
// +kubebuilder:printcolumn:name="Images",type=integer,JSONPath=`.status.exportedResources.imageVulnerabilities`
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.exportedResources.nodeVulnerabilities`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ResultsExporter is the Schema for the resultsexporters API
type ResultsExporter struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ResultsExporter
	// +required
	Spec ResultsExporterSpec `json:"spec"`

	// status defines the observed state of ResultsExporter
	// +optional
	Status ResultsExporterStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ResultsExporterList contains a list of ResultsExporter
type ResultsExporterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResultsExporter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResultsExporter{}, &ResultsExporterList{})
}
