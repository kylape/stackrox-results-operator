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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kylape/stackrox-results-operator/api/security/v1alpha1"
	resultsv1alpha1 "github.com/kylape/stackrox-results-operator/api/v1alpha1"
	"github.com/kylape/stackrox-results-operator/pkg/central"
)

// ResultsExporterReconciler reconciles a ResultsExporter object
type ResultsExporterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=results.stackrox.io,resources=resultsexporters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=resultsexporters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=resultsexporters/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.stackrox.io,resources=alerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stackrox.io,resources=alerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.stackrox.io,resources=clusteralerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stackrox.io,resources=clusteralerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.stackrox.io,resources=imagevulnerabilities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stackrox.io,resources=imagevulnerabilities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.stackrox.io,resources=nodevulnerabilities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stackrox.io,resources=nodevulnerabilities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.stackrox.io,resources=securityresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.stackrox.io,resources=clustersecurityresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

const (
	// Condition types
	TypeReady            = "Ready"
	TypeCentralConnected = "CentralConnected"
	TypeSyncing          = "Syncing"

	// Default sync interval
	defaultSyncInterval = 5 * time.Minute
)

// Reconcile implements the reconciliation loop for ResultsExporter
func (r *ResultsExporterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling ResultsExporter")

	// Fetch the ResultsExporter instance
	exporter := &resultsv1alpha1.ResultsExporter{}
	if err := r.Get(ctx, req.NamespacedName, exporter); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("ResultsExporter resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ResultsExporter")
		return ctrl.Result{}, err
	}

	// Initialize status if needed
	if exporter.Status.Conditions == nil {
		exporter.Status.Conditions = []metav1.Condition{}
	}

	// Create Central client
	centralClient, err := r.createCentralClient(ctx, exporter)
	if err != nil {
		logger.Error(err, "Failed to create Central client")
		r.setCondition(exporter, TypeCentralConnected, metav1.ConditionFalse,
			"ConnectionFailed", fmt.Sprintf("Failed to connect to Central: %v", err))
		r.setCondition(exporter, TypeReady, metav1.ConditionFalse,
			"CentralConnectionFailed", "Cannot connect to Central")
		if updateErr := r.Status().Update(ctx, exporter); updateErr != nil {
			logger.Error(updateErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	// Test connection
	if err := centralClient.TestConnection(ctx); err != nil {
		logger.Error(err, "Central connection test failed")
		r.setCondition(exporter, TypeCentralConnected, metav1.ConditionFalse,
			"ConnectionTestFailed", fmt.Sprintf("Connection test failed: %v", err))
		r.setCondition(exporter, TypeReady, metav1.ConditionFalse,
			"CentralConnectionTestFailed", "Connection test to Central failed")
		if updateErr := r.Status().Update(ctx, exporter); updateErr != nil {
			logger.Error(updateErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	logger.Info("Successfully connected to Central")
	r.setCondition(exporter, TypeCentralConnected, metav1.ConditionTrue,
		"Connected", "Successfully connected to Central")

	// Start sync
	syncStartTime := time.Now()
	r.setCondition(exporter, TypeSyncing, metav1.ConditionTrue,
		"SyncInProgress", "Syncing data from Central")
	exporter.Status.LastSyncTime = &metav1.Time{Time: syncStartTime}

	if err := r.Status().Update(ctx, exporter); err != nil {
		logger.Error(err, "Failed to update status before sync")
	}

	// Perform sync based on mode
	exportCounts, syncErr := r.syncData(ctx, exporter, centralClient)

	// Update status after sync
	syncDuration := time.Since(syncStartTime)
	exporter.Status.SyncDuration = &metav1.Duration{Duration: syncDuration}
	exporter.Status.ObservedGeneration = exporter.Generation

	if syncErr != nil {
		logger.Error(syncErr, "Sync failed")
		exporter.Status.LastSyncError = syncErr.Error()
		exporter.Status.ConsecutiveFailures++
		r.setCondition(exporter, TypeSyncing, metav1.ConditionFalse,
			"SyncFailed", fmt.Sprintf("Sync failed: %v", syncErr))
		r.setCondition(exporter, TypeReady, metav1.ConditionFalse,
			"SyncFailed", "Data sync from Central failed")
	} else {
		logger.Info("Sync completed successfully",
			"duration", syncDuration,
			"alerts", exportCounts.Alerts,
			"images", exportCounts.ImageVulnerabilities,
			"nodes", exportCounts.NodeVulnerabilities)

		exporter.Status.LastSuccessfulSync = &metav1.Time{Time: syncStartTime}
		exporter.Status.LastSyncError = ""
		exporter.Status.ConsecutiveFailures = 0
		exporter.Status.ExportedResources = exportCounts
		r.setCondition(exporter, TypeSyncing, metav1.ConditionFalse,
			"SyncCompleted", fmt.Sprintf("Sync completed in %v", syncDuration))
		r.setCondition(exporter, TypeReady, metav1.ConditionTrue,
			"SyncSuccessful", "Data successfully synced from Central")
	}

	// Update status
	if err := r.Status().Update(ctx, exporter); err != nil {
		logger.Error(err, "Failed to update status after sync")
		return ctrl.Result{}, err
	}

	// Calculate next sync interval
	syncInterval := defaultSyncInterval
	if exporter.Spec.SyncInterval != nil {
		syncInterval = exporter.Spec.SyncInterval.Duration
	}

	logger.Info("Requeuing for next sync", "interval", syncInterval)
	return ctrl.Result{RequeueAfter: syncInterval}, nil
}

// createCentralClient creates a Central API client from the ResultsExporter config
func (r *ResultsExporterReconciler) createCentralClient(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter) (*central.Client, error) {
	config := central.Config{
		Endpoint:       exporter.Spec.Central.Endpoint,
		TLSConfig:      exporter.Spec.Central.TLSConfig,
		AuthSecretName: exporter.Spec.Central.AuthSecretName,
		Namespace:      exporter.Spec.Central.AuthSecretNamespace,
		K8sClient:      r.Client,
	}

	return central.New(ctx, config)
}

// syncData syncs data from Central based on the export mode
func (r *ResultsExporterReconciler) syncData(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (*resultsv1alpha1.ExportedResourceCounts, error) {
	mode := exporter.Spec.Exports.Mode
	if mode == "" {
		mode = "individual" // default
	}

	counts := &resultsv1alpha1.ExportedResourceCounts{}

	// Sync based on mode
	switch mode {
	case "individual":
		return r.syncIndividualMode(ctx, exporter, centralClient)
	case "aggregated":
		return r.syncAggregatedMode(ctx, exporter, centralClient)
	case "both":
		// Sync both modes
		individualCounts, err1 := r.syncIndividualMode(ctx, exporter, centralClient)
		_, err2 := r.syncAggregatedMode(ctx, exporter, centralClient)

		if err1 != nil || err2 != nil {
			return counts, errors.Errorf("sync errors - individual: %v, aggregated: %v", err1, err2)
		}

		// Use individual counts for status (they're more detailed)
		return individualCounts, nil
	default:
		return counts, errors.Errorf("unknown export mode: %s", mode)
	}
}

// syncIndividualMode syncs data in individual CRD mode
func (r *ResultsExporterReconciler) syncIndividualMode(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (*resultsv1alpha1.ExportedResourceCounts, error) {
	logger := log.FromContext(ctx)
	logger.Info("Syncing in individual mode")

	counts := &resultsv1alpha1.ExportedResourceCounts{}

	// Sync alerts if enabled
	if exporter.Spec.Exports.Alerts != nil && exporter.Spec.Exports.Alerts.Enabled {
		alertCount, err := r.syncAlertsIndividual(ctx, exporter, centralClient)
		if err != nil {
			return counts, errors.Wrap(err, "failed to sync alerts")
		}
		counts.Alerts = alertCount
	}

	// Sync image vulnerabilities if enabled
	if exporter.Spec.Exports.ImageVulnerabilities != nil && exporter.Spec.Exports.ImageVulnerabilities.Enabled {
		imageCount, err := r.syncImageVulnerabilitiesIndividual(ctx, exporter, centralClient)
		if err != nil {
			return counts, errors.Wrap(err, "failed to sync image vulnerabilities")
		}
		counts.ImageVulnerabilities = imageCount
	}

	// Sync node vulnerabilities if enabled
	if exporter.Spec.Exports.NodeVulnerabilities != nil && exporter.Spec.Exports.NodeVulnerabilities.Enabled {
		nodeCount, err := r.syncNodeVulnerabilitiesIndividual(ctx, exporter, centralClient)
		if err != nil {
			return counts, errors.Wrap(err, "failed to sync node vulnerabilities")
		}
		counts.NodeVulnerabilities = nodeCount
	}

	return counts, nil
}

// syncAggregatedMode syncs data in aggregated CRD mode
func (r *ResultsExporterReconciler) syncAggregatedMode(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (*resultsv1alpha1.ExportedResourceCounts, error) {
	logger := log.FromContext(ctx)
	logger.Info("Syncing in aggregated mode")

	// TODO: Implement aggregated mode sync
	// This will create SecurityResults and ClusterSecurityResults CRDs

	counts := &resultsv1alpha1.ExportedResourceCounts{}
	return counts, nil
}

// syncAlertsIndividual syncs alerts as individual Alert CRDs
func (r *ResultsExporterReconciler) syncAlertsIndividual(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (int, error) {
	logger := log.FromContext(ctx)
	logger.Info("Syncing alerts in individual mode")

	config := exporter.Spec.Exports.Alerts
	if config == nil {
		return 0, nil
	}

	// Build list options
	opts := central.ListAlertsOptions{
		ExcludeResolved: config.Filters != nil && config.Filters.ExcludeResolved,
		Limit:           config.MaxPerNamespace,
	}

	if config.Filters != nil {
		opts.MinSeverity = config.Filters.MinSeverity
		opts.LifecycleStages = config.Filters.LifecycleStages
	}

	// Fetch alerts from Central
	alerts, err := centralClient.ListAlerts(ctx, opts)
	if err != nil {
		return 0, errors.Wrap(err, "failed to list alerts from Central")
	}

	logger.Info("Retrieved alerts from Central", "count", len(alerts))

	// Create/update Alert CRDs (namespace-scoped) and ClusterAlert CRDs (cluster-scoped)
	createdCount := 0
	for _, alert := range alerts {
		// Determine if this is a namespace-scoped or cluster-scoped alert
		// Check both formats: list endpoint has Deployment at top level, detail endpoint has it in Entity
		var namespace string
		if alert.Deployment != nil && alert.Deployment.Namespace != "" {
			namespace = alert.Deployment.Namespace
		} else if alert.Entity != nil && alert.Entity.Deployment != nil && alert.Entity.Deployment.Namespace != "" {
			namespace = alert.Entity.Deployment.Namespace
		}

		if namespace != "" {
			// Create/update namespace-scoped Alert
			crd := alert.ConvertToCRD()
			crd.Namespace = namespace

			// Create or update
			existing := &securityv1alpha1.Alert{}
			err := r.Get(ctx, client.ObjectKey{Namespace: crd.Namespace, Name: crd.Name}, existing)

			if apierrors.IsNotFound(err) {
				// Create new resource (with empty spec)
				if err := r.Create(ctx, crd); err != nil {
					logger.Error(err, "Failed to create Alert CRD", "name", crd.Name)
					continue
				}
				logger.V(1).Info("Created Alert CRD", "name", crd.Name, "namespace", crd.Namespace)

				// Update status subresource
				if err := r.Status().Update(ctx, crd); err != nil {
					logger.Error(err, "Failed to update Alert status", "name", crd.Name)
					continue
				}
				createdCount++
			} else if err == nil {
				// Resource exists - update status subresource
				crd.ResourceVersion = existing.ResourceVersion
				if err := r.Status().Update(ctx, crd); err != nil {
					logger.Error(err, "Failed to update Alert status", "name", crd.Name)
					continue
				}
				createdCount++
				logger.V(1).Info("Updated Alert status", "name", crd.Name, "namespace", crd.Namespace)
			} else {
				logger.Error(err, "Failed to get Alert CRD", "name", crd.Name)
				continue
			}
		} else {
			// Create/update cluster-scoped ClusterAlert
			crd := alert.ConvertToClusterCRD()

			// Create or update
			existing := &securityv1alpha1.ClusterAlert{}
			err := r.Get(ctx, client.ObjectKey{Name: crd.Name}, existing)

			if apierrors.IsNotFound(err) {
				// Create new resource (with empty spec)
				if err := r.Create(ctx, crd); err != nil {
					logger.Error(err, "Failed to create ClusterAlert CRD", "name", crd.Name)
					continue
				}
				logger.V(1).Info("Created ClusterAlert CRD", "name", crd.Name)

				// Update status subresource
				if err := r.Status().Update(ctx, crd); err != nil {
					logger.Error(err, "Failed to update ClusterAlert status", "name", crd.Name)
					continue
				}
				createdCount++
			} else if err == nil {
				// Resource exists - update status subresource
				crd.ResourceVersion = existing.ResourceVersion
				if err := r.Status().Update(ctx, crd); err != nil {
					logger.Error(err, "Failed to update ClusterAlert status", "name", crd.Name)
					continue
				}
				createdCount++
				logger.V(1).Info("Updated ClusterAlert status", "name", crd.Name)
			} else {
				logger.Error(err, "Failed to get ClusterAlert CRD", "name", crd.Name)
				continue
			}
		}
	}

	logger.Info("Synced alerts", "created/updated", createdCount)
	return createdCount, nil
}

// syncImageVulnerabilitiesIndividual syncs image vulnerabilities as individual CRDs
func (r *ResultsExporterReconciler) syncImageVulnerabilitiesIndividual(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (int, error) {
	logger := log.FromContext(ctx)
	logger.Info("Syncing image vulnerabilities in individual mode")

	config := exporter.Spec.Exports.ImageVulnerabilities
	if config == nil {
		return 0, nil
	}

	// Build list options
	opts := central.ListImageVulnerabilitiesOptions{
		MaxImages: config.MaxImages,
	}

	if config.Filters != nil {
		opts.MinSeverity = config.Filters.MinSeverity
		opts.FixableOnly = config.Filters.FixableOnly
		opts.MaxCVEsPerImage = config.Filters.MaxCVEsPerResource
	}

	// Fetch image vulnerabilities from Central
	images, err := centralClient.ListImageVulnerabilities(ctx, opts)
	if err != nil {
		return 0, errors.Wrap(err, "failed to list image vulnerabilities from Central")
	}

	logger.Info("Retrieved image vulnerabilities from Central", "count", len(images))

	// Create/update ImageVulnerability CRDs
	createdCount := 0
	for _, img := range images {
		crd := img.ConvertToCRD()

		// ImageVulnerability is cluster-scoped
		existing := &securityv1alpha1.ImageVulnerability{}
		err := r.Get(ctx, client.ObjectKey{Name: crd.Name}, existing)

		if apierrors.IsNotFound(err) {
			// Create new resource (with empty spec)
			if err := r.Create(ctx, crd); err != nil {
				logger.Error(err, "Failed to create ImageVulnerability CRD", "name", crd.Name)
				continue
			}
			logger.V(1).Info("Created ImageVulnerability CRD", "name", crd.Name)

			// Update status subresource
			if err := r.Status().Update(ctx, crd); err != nil {
				logger.Error(err, "Failed to update ImageVulnerability status", "name", crd.Name)
				continue
			}
			createdCount++
		} else if err == nil {
			// Resource exists - update status subresource
			crd.ResourceVersion = existing.ResourceVersion
			if err := r.Status().Update(ctx, crd); err != nil {
				logger.Error(err, "Failed to update ImageVulnerability status", "name", crd.Name)
				continue
			}
			createdCount++
			logger.V(1).Info("Updated ImageVulnerability status", "name", crd.Name)
		} else {
			logger.Error(err, "Failed to get ImageVulnerability CRD", "name", crd.Name)
		}
	}

	logger.Info("Synced image vulnerabilities", "created/updated", createdCount)
	return createdCount, nil
}

// syncNodeVulnerabilitiesIndividual syncs node vulnerabilities as individual CRDs
func (r *ResultsExporterReconciler) syncNodeVulnerabilitiesIndividual(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client) (int, error) {
	logger := log.FromContext(ctx)
	logger.Info("Syncing node vulnerabilities in individual mode")

	config := exporter.Spec.Exports.NodeVulnerabilities
	if config == nil {
		return 0, nil
	}

	minSeverity := ""
	maxCVEs := 50

	if config.Filters != nil {
		minSeverity = config.Filters.MinSeverity
		maxCVEs = config.Filters.MaxCVEsPerResource
	}

	// Fetch node vulnerabilities from Central
	nodes, err := centralClient.ListNodeVulnerabilities(ctx, minSeverity, maxCVEs)
	if err != nil {
		return 0, errors.Wrap(err, "failed to list node vulnerabilities from Central")
	}

	logger.Info("Retrieved node vulnerabilities from Central", "count", len(nodes))

	// Create/update NodeVulnerability CRDs
	createdCount := 0
	for _, node := range nodes {
		crd := node.ConvertToCRD()

		// NodeVulnerability is cluster-scoped
		existing := &securityv1alpha1.NodeVulnerability{}
		err := r.Get(ctx, client.ObjectKey{Name: crd.Name}, existing)

		if apierrors.IsNotFound(err) {
			// Create new resource (with empty spec)
			if err := r.Create(ctx, crd); err != nil {
				logger.Error(err, "Failed to create NodeVulnerability CRD", "name", crd.Name)
				continue
			}
			logger.V(1).Info("Created NodeVulnerability CRD", "name", crd.Name)

			// Update status subresource
			if err := r.Status().Update(ctx, crd); err != nil {
				logger.Error(err, "Failed to update NodeVulnerability status", "name", crd.Name)
				continue
			}
			createdCount++
		} else if err == nil {
			// Resource exists - update status subresource
			crd.ResourceVersion = existing.ResourceVersion
			if err := r.Status().Update(ctx, crd); err != nil {
				logger.Error(err, "Failed to update NodeVulnerability status", "name", crd.Name)
				continue
			}
			createdCount++
			logger.V(1).Info("Updated NodeVulnerability status", "name", crd.Name)
		} else {
			logger.Error(err, "Failed to get NodeVulnerability CRD", "name", crd.Name)
		}
	}

	logger.Info("Synced node vulnerabilities", "created/updated", createdCount)
	return createdCount, nil
}

// setCondition sets a condition on the ResultsExporter status
func (r *ResultsExporterReconciler) setCondition(exporter *resultsv1alpha1.ResultsExporter, conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: exporter.Generation,
	}

	meta.SetStatusCondition(&exporter.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResultsExporterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&resultsv1alpha1.ResultsExporter{}).
		Named("resultsexporter").
		Complete(r)
}
