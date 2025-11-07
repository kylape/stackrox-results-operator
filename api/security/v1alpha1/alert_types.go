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

// AlertSpec defines the desired state of Alert
// NOTE: This is a read-only resource created by the operator.
// Spec is intentionally empty - all data is in Status.
type AlertSpec struct {
	// This resource is managed by the operator and has no user-configurable spec.
}

// AlertEntity describes the Kubernetes entity that violated the policy
type AlertEntity struct {
	// Type of entity (Deployment, Pod, Image, Node, Resource)
	// +optional
	Type string `json:"type,omitempty"`

	// Entity name (deployment name, image name, resource name, etc.)
	// +optional
	Name string `json:"name,omitempty"`

	// Entity ID
	// +optional
	ID string `json:"id,omitempty"`

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

// AlertStatus defines the observed state of Alert
// This contains all the security finding data from StackRox Central
type AlertStatus struct {
	// Policy information
	// +optional
	PolicyID string `json:"policyId,omitempty"`

	// +optional
	PolicyName string `json:"policyName,omitempty"`

	// +optional
	// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW
	PolicySeverity string `json:"policySeverity,omitempty"`

	// +optional
	PolicyDescription string `json:"policyDescription,omitempty"`

	// +optional
	PolicyCategories []string `json:"policyCategories,omitempty"`

	// Lifecycle stage when the violation was detected
	// +optional
	// +kubebuilder:validation:Enum=DEPLOY;RUNTIME
	LifecycleStage string `json:"lifecycleStage,omitempty"`

	// Entity that violated the policy
	// +optional
	Entity *AlertEntity `json:"entity,omitempty"`

	// Violation details
	// +optional
	Violations []Violation `json:"violations,omitempty"`

	// When this alert occurred
	// +optional
	Time *metav1.Time `json:"time,omitempty"`

	// When this alert was first triggered
	// +optional
	FirstOccurred *metav1.Time `json:"firstOccurred,omitempty"`

	// Current state of the alert
	// +kubebuilder:validation:Enum=ACTIVE;RESOLVED;ATTEMPTED
	// +optional
	State string `json:"state,omitempty"`

	// When the alert was resolved
	// +optional
	ResolvedAt *metav1.Time `json:"resolvedAt,omitempty"`

	// Note explaining resolution
	// +optional
	ResolutionNote string `json:"resolutionNote,omitempty"`

	// Enforcement action taken
	// +optional
	EnforcementAction string `json:"enforcementAction,omitempty"`

	// Number of times enforcement was applied
	// +optional
	EnforcementCount int `json:"enforcementCount,omitempty"`

	// Current condition message
	// +optional
	ConditionMessage string `json:"conditionMessage,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=alerts,scope=Namespaced
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.policyName`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.status.policySeverity`
// +kubebuilder:printcolumn:name="Entity Type",type=string,JSONPath=`.status.entity.type`
// +kubebuilder:printcolumn:name="Entity",type=string,JSONPath=`.status.entity.name`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Lifecycle",type=string,JSONPath=`.status.lifecycleStage`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.status.time`

// Alert is the Schema for the alerts API
type Alert struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of Alert
	// +required
	Spec AlertSpec `json:"spec"`

	// status defines the observed state of Alert
	// +optional
	Status AlertStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// AlertList contains a list of Alert
type AlertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Alert `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Alert{}, &AlertList{})
}
