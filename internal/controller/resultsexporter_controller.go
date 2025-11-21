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
	"github.com/stackrox/rox/generated/storage"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
// +kubebuilder:rbac:groups=results.stackrox.io,resources=alerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=alerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=clusteralerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=clusteralerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=imagevulnerabilities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=imagevulnerabilities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=nodevulnerabilities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=nodevulnerabilities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=securityresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=securityresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=results.stackrox.io,resources=clustersecurityresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=results.stackrox.io,resources=clustersecurityresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

const (
	// Condition types
	TypeReady            = "Ready"
	TypeCentralConnected = "CentralConnected"
	TypeSyncing          = "Syncing"

	// Finalizer name
	finalizerName = "results.stackrox.io/cleanup"

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

	// Handle deletion
	if !exporter.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(exporter, finalizerName) {
			logger.Info("ResultsExporter is being deleted, cleaning up managed resources")
			// Cleanup all managed resources
			if err := r.cleanupAllManagedResources(ctx, exporter); err != nil {
				logger.Error(err, "Failed to cleanup managed resources")
				return ctrl.Result{}, err
			}

			// Remove finalizer
			logger.Info("Removing finalizer")
			controllerutil.RemoveFinalizer(exporter, finalizerName)
			if err := r.Update(ctx, exporter); err != nil {
				logger.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			logger.Info("Finalizer removed, deletion will proceed")
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(exporter, finalizerName) {
		logger.Info("Adding finalizer")
		controllerutil.AddFinalizer(exporter, finalizerName)
		if err := r.Update(ctx, exporter); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		// Requeue to continue with normal reconciliation
		return ctrl.Result{Requeue: true}, nil
	}

	// Initialize status if needed
	if exporter.Status.Conditions == nil {
		exporter.Status.Conditions = []metav1.Condition{}
	}

	// Determine if we need to sync
	needsSync := false
	var skipReason string

	// Always sync if generation changed (spec changed)
	if exporter.Status.ObservedGeneration != exporter.Generation {
		needsSync = true
		logger.Info("Spec changed, sync needed",
			"generation", exporter.Generation,
			"observedGeneration", exporter.Status.ObservedGeneration)
	} else if exporter.Status.LastSuccessfulSync == nil {
		// First sync (never synced before)
		needsSync = true
		logger.Info("First sync needed")
	} else {
		// Check if it's time for periodic sync
		syncInterval := defaultSyncInterval
		if exporter.Spec.SyncInterval != nil {
			syncInterval = exporter.Spec.SyncInterval.Duration
		}

		nextSyncTime := exporter.Status.LastSuccessfulSync.Add(syncInterval)
		if time.Now().After(nextSyncTime) {
			needsSync = true
			logger.Info("Periodic sync due",
				"lastSync", exporter.Status.LastSuccessfulSync.Time,
				"interval", syncInterval,
				"nextSync", nextSyncTime)
		} else {
			skipReason = fmt.Sprintf("Next sync at %v", nextSyncTime.Format(time.RFC3339))
		}
	}

	// Skip sync if not needed
	if !needsSync {
		logger.V(1).Info("Sync not needed, skipping", "reason", skipReason)
		// Still requeue for next periodic sync
		syncInterval := defaultSyncInterval
		if exporter.Spec.SyncInterval != nil {
			syncInterval = exporter.Spec.SyncInterval.Duration
		}

		// Calculate time until next sync
		if exporter.Status.LastSuccessfulSync != nil {
			nextSyncTime := exporter.Status.LastSuccessfulSync.Add(syncInterval)
			timeUntilNextSync := time.Until(nextSyncTime)
			if timeUntilNextSync > 0 {
				logger.V(1).Info("Requeuing for next periodic sync", "after", timeUntilNextSync)
				return ctrl.Result{RequeueAfter: timeUntilNextSync}, nil
			}
		}

		// Fallback to default interval
		return ctrl.Result{RequeueAfter: syncInterval}, nil
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

	// Calculate next sync interval with exponential backoff on failures
	var syncInterval time.Duration

	if syncErr != nil && exporter.Status.ConsecutiveFailures > 0 {
		// Exponential backoff on failures: 1s, 2s, 4s, 8s, 16s, ... up to 1 hour
		// Formula: 2^(failures-1) seconds, capped at 3600 seconds (1 hour)
		backoffSeconds := 1 << (exporter.Status.ConsecutiveFailures - 1) // 2^(n-1)
		if backoffSeconds > 3600 {                                       // Cap at 1 hour
			backoffSeconds = 3600
		}
		syncInterval = time.Duration(backoffSeconds) * time.Second
		logger.Info("Applying exponential backoff due to failures",
			"consecutiveFailures", exporter.Status.ConsecutiveFailures,
			"interval", syncInterval)
	} else {
		// Normal sync interval when no failures
		syncInterval = defaultSyncInterval
		if exporter.Spec.SyncInterval != nil {
			syncInterval = exporter.Spec.SyncInterval.Duration
		}
		logger.Info("Requeuing for next sync", "interval", syncInterval)
	}

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

	counts := &resultsv1alpha1.ExportedResourceCounts{}

	// 1. Sync SecurityResults (namespace-scoped: alerts + image vulns)
	if err := r.syncSecurityResults(ctx, exporter, centralClient, counts); err != nil {
		return counts, errors.Wrap(err, "failed to sync SecurityResults")
	}

	// 2. Sync ClusterSecurityResults (cluster-scoped: node vulns)
	if err := r.syncClusterSecurityResults(ctx, exporter, centralClient, counts); err != nil {
		return counts, errors.Wrap(err, "failed to sync ClusterSecurityResults")
	}

	logger.Info("Completed aggregated mode sync",
		"alerts", counts.Alerts,
		"imageVulns", counts.ImageVulnerabilities,
		"nodeVulns", counts.NodeVulnerabilities)

	return counts, nil
}

// syncSecurityResults creates/updates SecurityResults CRs (one per namespace)
func (r *ResultsExporterReconciler) syncSecurityResults(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client, counts *resultsv1alpha1.ExportedResourceCounts) error {
	logger := log.FromContext(ctx)
	logger.Info("Syncing SecurityResults")

	// Fetch alerts from Central
	var alerts []*storage.ListAlert
	if exporter.Spec.Exports.Alerts != nil && exporter.Spec.Exports.Alerts.Enabled {
		config := exporter.Spec.Exports.Alerts
		opts := central.ListAlertsOptions{
			ExcludeResolved: config.Filters != nil && config.Filters.ExcludeResolved,
			Limit:           config.MaxPerNamespace,
		}
		if config.Filters != nil {
			opts.MinSeverity = config.Filters.MinSeverity
			opts.LifecycleStages = config.Filters.LifecycleStages
		}

		var err error
		alerts, err = centralClient.ListAlerts(ctx, opts)
		if err != nil {
			return errors.Wrap(err, "failed to list alerts")
		}
		logger.Info("Retrieved alerts from Central", "count", len(alerts))
	}

	// Fetch image vulnerabilities from Central
	var images []*storage.Image
	if exporter.Spec.Exports.ImageVulnerabilities != nil && exporter.Spec.Exports.ImageVulnerabilities.Enabled {
		config := exporter.Spec.Exports.ImageVulnerabilities
		opts := central.ListImageVulnerabilitiesOptions{
			MaxImages: config.MaxImages,
		}
		if config.Filters != nil {
			opts.MinSeverity = config.Filters.MinSeverity
			opts.FixableOnly = config.Filters.FixableOnly
			opts.MaxCVEsPerImage = config.Filters.MaxCVEsPerResource
		}

		var err error
		images, err = centralClient.ListImages(ctx, opts)
		if err != nil {
			return errors.Wrap(err, "failed to list image vulnerabilities")
		}
		logger.Info("Retrieved image vulnerabilities from Central", "count", len(images))
	}

	// Group data by namespace
	namespaceData := make(map[string]*securityv1alpha1.SecurityResultsStatus)

	// Group alerts by namespace
	for _, alert := range alerts {
		namespace := r.extractNamespaceFromAlert(alert)
		if namespace == "" {
			// Skip cluster-scoped alerts in SecurityResults (they don't belong to a namespace)
			continue
		}

		if namespaceData[namespace] == nil {
			namespaceData[namespace] = &securityv1alpha1.SecurityResultsStatus{
				Namespace: namespace,
			}
		}

		// Convert alert to AlertData
		alertData := r.convertAlertToAlertData(alert)
		namespaceData[namespace].Alerts = append(namespaceData[namespace].Alerts, alertData)
		counts.Alerts++
	}

	// Query Central for deployments to determine which images are used in which namespaces
	deployments, err := centralClient.ListDeployments(ctx)
	if err != nil {
		logger.Error(err, "Failed to list deployments from Central")
		// Continue without image filtering
		deployments = nil
	}

	imagesByNamespace := central.GetImagesByNamespaceFromDeployments(deployments)

	// Count total unique images across all namespaces
	uniqueImages := make(map[string]bool)
	for _, nsImages := range imagesByNamespace {
		for imgName := range nsImages {
			uniqueImages[imgName] = true
		}
	}

	logger.V(1).Info("Built image-to-namespace mapping from Central deployments",
		"namespaceCount", len(imagesByNamespace),
		"deploymentCount", len(deployments),
		"uniqueImages", len(uniqueImages))

	// Group image vulnerabilities by namespace based on actual pod usage
	matchedImages := 0
	unmatchedImages := 0
	for _, img := range images {
		if img == nil || img.GetName() == nil {
			continue
		}

		// Convert image to ImageVulnerabilityData
		imgData := r.convertImageToImageVulnData(img)
		imageFullName := img.GetName().GetFullName()

		// Add this image vulnerability to each namespace that uses it
		addedToAnyNamespace := false
		for ns, images := range imagesByNamespace {
			if images[imageFullName] {
				// Ensure namespace exists in namespaceData
				if namespaceData[ns] == nil {
					namespaceData[ns] = &securityv1alpha1.SecurityResultsStatus{
						Namespace: ns,
					}
				}
				namespaceData[ns].ImageVulnerabilities = append(namespaceData[ns].ImageVulnerabilities, imgData)
				addedToAnyNamespace = true
			}
		}

		if addedToAnyNamespace {
			counts.ImageVulnerabilities++
			matchedImages++
		} else {
			unmatchedImages++
			logger.V(2).Info("Image vulnerability not matched to any namespace",
				"imageName", imageFullName)
		}
	}

	logger.Info("Image vulnerability matching complete",
		"totalImages", len(images),
		"matchedImages", matchedImages,
		"unmatchedImages", unmatchedImages,
		"uniqueDeployedImages", len(uniqueImages))

	// Create/update SecurityResults CR for each namespace
	now := metav1.Now()
	for namespace, status := range namespaceData {
		// Check if namespace exists first
		ns := &corev1.Namespace{}
		if err := r.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Info("Skipping SecurityResults for non-existent namespace",
					"namespace", namespace,
					"alertCount", len(status.Alerts),
					"imageCount", len(status.ImageVulnerabilities))
				continue
			}
			logger.Error(err, "Failed to check namespace existence", "namespace", namespace)
			continue
		}

		// Calculate summary
		summary := r.calculateSecurityResultsSummary(status)

		sr := &securityv1alpha1.SecurityResults{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "security-results",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "results-operator",
					"results.stackrox.io/exporter": exporter.Name,
				},
			},
			Spec: securityv1alpha1.SecurityResultsSpec{},
			Status: securityv1alpha1.SecurityResultsStatus{
				Namespace:            namespace,
				Alerts:               status.Alerts,
				ImageVulnerabilities: status.ImageVulnerabilities,
				Summary:              summary,
				LastUpdated:          &now,
			},
		}

		// Create or update
		existing := &securityv1alpha1.SecurityResults{}
		err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "security-results"}, existing)

		if apierrors.IsNotFound(err) {
			// Create new resource
			if err := r.Create(ctx, sr); err != nil {
				logger.Error(err, "Failed to create SecurityResults", "namespace", namespace)
				continue
			}
			logger.V(1).Info("Created SecurityResults", "namespace", namespace)

			// Update status subresource
			if err := r.Status().Update(ctx, sr); err != nil {
				logger.Error(err, "Failed to update SecurityResults status", "namespace", namespace)
			}
		} else if err == nil {
			// Update existing resource - only update status since Spec is empty
			existing.Status = sr.Status
			if err := r.Status().Update(ctx, existing); err != nil {
				logger.Error(err, "Failed to update SecurityResults status", "namespace", namespace)
				continue
			}
			logger.V(1).Info("Updated SecurityResults", "namespace", namespace)
		} else {
			logger.Error(err, "Failed to get SecurityResults", "namespace", namespace)
			continue
		}
	}

	logger.Info("Synced SecurityResults", "namespaces", len(namespaceData))
	return nil
}

// syncClusterSecurityResults creates/updates the ClusterSecurityResults CR
func (r *ResultsExporterReconciler) syncClusterSecurityResults(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, centralClient *central.Client, counts *resultsv1alpha1.ExportedResourceCounts) error {
	logger := log.FromContext(ctx)
	logger.Info("Syncing ClusterSecurityResults")

	// Fetch node vulnerabilities from Central
	var nodes []*storage.Node
	if exporter.Spec.Exports.NodeVulnerabilities != nil && exporter.Spec.Exports.NodeVulnerabilities.Enabled {
		config := exporter.Spec.Exports.NodeVulnerabilities

		minSeverity := ""
		maxCVEsPerNode := 50 // default
		if config.Filters != nil {
			minSeverity = config.Filters.MinSeverity
			if config.Filters.MaxCVEsPerResource > 0 {
				maxCVEsPerNode = config.Filters.MaxCVEsPerResource
			}
		}

		var err error
		nodes, err = centralClient.ListNodeVulnerabilities(ctx, minSeverity, maxCVEsPerNode)
		if err != nil {
			return errors.Wrap(err, "failed to list node vulnerabilities")
		}
		logger.Info("Retrieved node vulnerabilities from Central", "count", len(nodes))
	}

	if len(nodes) == 0 {
		logger.Info("No node vulnerabilities to sync")
		return nil
	}

	// Convert nodes to NodeVulnerabilityData
	nodeData := make([]securityv1alpha1.NodeVulnerabilityData, 0, len(nodes))
	for _, node := range nodes {
		nodeData = append(nodeData, r.convertNodeToNodeVulnData(node))
		counts.NodeVulnerabilities++
	}

	// Create/update ClusterSecurityResults
	now := metav1.Now()

	// Calculate summary from node data
	summary := r.calculateClusterSecurityResultsSummary(nodeData)

	csr := &securityv1alpha1.ClusterSecurityResults{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-security-results",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "results-operator",
				"results.stackrox.io/exporter": exporter.Name,
			},
		},
		Spec: securityv1alpha1.ClusterSecurityResultsSpec{},
		Status: securityv1alpha1.ClusterSecurityResultsStatus{
			NodeVulnerabilities: nodeData,
			Summary:             summary,
			LastUpdated:         &now,
		},
	}

	// Create or update
	existing := &securityv1alpha1.ClusterSecurityResults{}
	err := r.Get(ctx, client.ObjectKey{Name: "cluster-security-results"}, existing)

	if apierrors.IsNotFound(err) {
		// Create new resource
		if err := r.Create(ctx, csr); err != nil {
			return errors.Wrap(err, "failed to create ClusterSecurityResults")
		}
		logger.Info("Created ClusterSecurityResults")

		// Update status subresource
		if err := r.Status().Update(ctx, csr); err != nil {
			return errors.Wrap(err, "failed to update ClusterSecurityResults status")
		}
	} else if err == nil {
		// Update existing resource - only update status since Spec is empty
		existing.Status = csr.Status
		if err := r.Status().Update(ctx, existing); err != nil {
			return errors.Wrap(err, "failed to update ClusterSecurityResults status")
		}
		logger.Info("Updated ClusterSecurityResults")
	} else {
		return errors.Wrap(err, "failed to get ClusterSecurityResults")
	}

	return nil
}

// Helper functions for data conversion

func (r *ResultsExporterReconciler) extractNamespaceFromAlert(alert *storage.ListAlert) string {
	// Check deployment first
	if deployment := alert.GetDeployment(); deployment != nil && deployment.GetNamespace() != "" {
		return deployment.GetNamespace()
	}
	// For resources, check common entity info (resource only has name field)
	if common := alert.GetCommonEntityInfo(); common != nil && common.GetNamespace() != "" {
		return common.GetNamespace()
	}
	return ""
}

func (r *ResultsExporterReconciler) convertAlertToAlertData(alert *storage.ListAlert) securityv1alpha1.AlertData {
	alertData := securityv1alpha1.AlertData{
		ID:             alert.GetId(),
		LifecycleStage: alert.GetLifecycleStage().String(),
		State:          alert.GetState().String(),
	}

	if policy := alert.GetPolicy(); policy != nil {
		alertData.PolicyID = policy.GetId()
		alertData.PolicyName = policy.GetName()
		alertData.PolicySeverity = central.NormalizeStorageSeverity(policy.GetSeverity())
		alertData.PolicyCategories = policy.GetCategories()
	}

	if alert.GetTime() != nil {
		alertData.Time = metav1.NewTime(alert.GetTime().AsTime())
	}

	// ListAlert doesn't have FirstOccurred or ResolvedAt, only Alert does
	// For aggregated mode with ListAlert, these fields won't be populated

	// Get common entity info (has cluster/namespace/resource type for resources)
	common := alert.GetCommonEntityInfo()

	// Convert entity from ListAlert
	if deployment := alert.GetDeployment(); deployment != nil {
		alertData.Entity = &securityv1alpha1.AlertEntity{
			Type:        "DEPLOYMENT",
			ID:          deployment.GetId(),
			Name:        deployment.GetName(),
			Namespace:   deployment.GetNamespace(),
			ClusterName: deployment.GetClusterName(),
			ClusterID:   deployment.GetClusterId(),
		}
	} else if resource := alert.GetResource(); resource != nil {
		alertData.Entity = &securityv1alpha1.AlertEntity{
			Name: resource.GetName(),
		}
		// Get cluster/namespace/resource type from common entity info
		if common != nil {
			alertData.Entity.ResourceType = common.GetResourceType().String()
			alertData.Entity.Type = common.GetResourceType().String()
			alertData.Entity.Namespace = common.GetNamespace()
			alertData.Entity.ClusterID = common.GetClusterId()
			alertData.Entity.ClusterName = common.GetClusterName()
		}
	}

	// ListAlert doesn't include violations, only Alert does
	// For aggregated mode with ListAlert, violations won't be populated

	return alertData
}

func (r *ResultsExporterReconciler) convertImageToImageVulnData(img *storage.Image) securityv1alpha1.ImageVulnerabilityData {
	// Reuse the conversion logic from ConvertImageToCRD
	vuln := central.ConvertImageToCRD(img, "")

	imgData := securityv1alpha1.ImageVulnerabilityData{
		Image: *vuln.Status.Image,
	}

	if vuln.Status.ScanTime != nil {
		imgData.ScanTime = *vuln.Status.ScanTime
	}

	if vuln.Status.Summary != nil {
		imgData.Summary = *vuln.Status.Summary
	}

	// Convert CVEs (limit to 50 as per CRD validation)
	if len(vuln.Status.CVEs) > 0 {
		maxCVEs := 50
		cveCount := len(vuln.Status.CVEs)
		if cveCount > maxCVEs {
			cveCount = maxCVEs
		}
		imgData.CVEs = vuln.Status.CVEs[:cveCount]
	}

	return imgData
}

func (r *ResultsExporterReconciler) convertNodeToNodeVulnData(node *storage.Node) securityv1alpha1.NodeVulnerabilityData {
	nodeData := securityv1alpha1.NodeVulnerabilityData{
		NodeName:      node.GetName(),
		OSImage:       node.GetOsImage(),
		KernelVersion: node.GetKernelVersion(),
	}

	// Extract scan data if available
	scan := node.GetScan()
	if scan != nil {
		if scanTime := scan.GetScanTime(); scanTime != nil {
			nodeData.ScanTime = metav1.NewTime(scanTime.AsTime())
		}

		// Calculate summary from components
		// storage.NodeScan doesn't have a pre-computed summary like the old type,
		// so we need to calculate it from the components
		summary := r.calculateNodeVulnerabilitySummary(scan.GetComponents())
		nodeData.Summary = *summary
	}

	return nodeData
}

// calculateNodeVulnerabilitySummary calculates vulnerability summary from node scan components
func (r *ResultsExporterReconciler) calculateNodeVulnerabilitySummary(components []*storage.EmbeddedNodeScanComponent) *securityv1alpha1.VulnerabilitySummary {
	summary := &securityv1alpha1.VulnerabilitySummary{}

	criticalCount := &securityv1alpha1.SeverityCount{}
	highCount := &securityv1alpha1.SeverityCount{}
	mediumCount := &securityv1alpha1.SeverityCount{}
	lowCount := &securityv1alpha1.SeverityCount{}

	// Aggregate vulnerabilities from all components
	for _, component := range components {
		for _, vuln := range component.GetVulnerabilities() {
			summary.Total++

			// Check if fixable
			if vuln.GetFixedBy() != "" {
				summary.FixableTotal++
			}

			// Count by severity
			severity := vuln.GetSeverity()
			fixable := vuln.GetFixedBy() != ""

			switch severity {
			case storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY:
				criticalCount.Total++
				if fixable {
					criticalCount.Fixable++
				}
			case storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY:
				highCount.Total++
				if fixable {
					highCount.Fixable++
				}
			case storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY:
				mediumCount.Total++
				if fixable {
					mediumCount.Fixable++
				}
			case storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY:
				lowCount.Total++
				if fixable {
					lowCount.Fixable++
				}
			}
		}
	}

	// Only include severity counts if non-zero
	if criticalCount.Total > 0 {
		summary.Critical = criticalCount
	}
	if highCount.Total > 0 {
		summary.High = highCount
	}
	if mediumCount.Total > 0 {
		summary.Medium = mediumCount
	}
	if lowCount.Total > 0 {
		summary.Low = lowCount
	}

	return summary
}

func (r *ResultsExporterReconciler) calculateSecurityResultsSummary(status *securityv1alpha1.SecurityResultsStatus) *securityv1alpha1.SecuritySummary {
	summary := &securityv1alpha1.SecuritySummary{}

	// Count alerts by severity
	for _, alert := range status.Alerts {
		summary.TotalAlerts++
		if alert.PolicySeverity == "CRITICAL" {
			summary.CriticalAlerts++
		} else if alert.PolicySeverity == "HIGH" {
			summary.HighAlerts++
		}
	}

	// Count CVEs across all images
	for _, img := range status.ImageVulnerabilities {
		summary.TotalCVEs += img.Summary.Total
		summary.FixableCVEs += img.Summary.FixableTotal
		if img.Summary.Critical != nil {
			summary.CriticalCVEs += img.Summary.Critical.Total
		}
		if img.Summary.High != nil {
			summary.HighCVEs += img.Summary.High.Total
		}
	}

	return summary
}

func (r *ResultsExporterReconciler) calculateClusterSecurityResultsSummary(nodeVulnerabilities []securityv1alpha1.NodeVulnerabilityData) *securityv1alpha1.ClusterSecuritySummary {
	summary := &securityv1alpha1.ClusterSecuritySummary{
		NodesScanned: len(nodeVulnerabilities),
	}

	// Count CVEs and nodes with critical/high vulns
	for _, node := range nodeVulnerabilities {
		summary.TotalCVEs += node.Summary.Total
		summary.FixableCVEs += node.Summary.FixableTotal

		hasCritical := node.Summary.Critical != nil && node.Summary.Critical.Total > 0
		hasHigh := node.Summary.High != nil && node.Summary.High.Total > 0

		if hasCritical {
			summary.NodesWithCritical++
		}
		if hasHigh {
			summary.NodesWithHigh++
		}
	}

	return summary
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

	// Track current alert IDs for cleanup
	currentAlertIDs := make(map[string]bool)

	// Create/update Alert CRDs (namespace-scoped) and ClusterAlert CRDs (cluster-scoped)
	createdCount := 0
	for _, alert := range alerts {
		// Track this alert ID
		currentAlertIDs[alert.GetId()] = true
		// Determine if this is a namespace-scoped or cluster-scoped alert
		// Extract namespace from the alert entity
		var namespace string
		if deployment := alert.GetDeployment(); deployment != nil && deployment.GetNamespace() != "" {
			namespace = deployment.GetNamespace()
		} else if resource := alert.GetResource(); resource != nil {
			// Resources might have namespace in common entity info
			if common := alert.GetCommonEntityInfo(); common != nil && common.GetNamespace() != "" {
				namespace = common.GetNamespace()
			}
		}

		if namespace != "" {
			// Create/update namespace-scoped Alert
			crd := central.ConvertListAlertToCRD(alert, exporter.Name)
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
			crd := central.ConvertListAlertToClusterCRD(alert, exporter.Name)

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

	// Cleanup stale alerts
	deletedCount, err := r.cleanupStaleAlerts(ctx, exporter, currentAlertIDs)
	if err != nil {
		logger.Error(err, "Failed to cleanup stale alerts")
		// Don't fail the sync, just log the error
	}
	if deletedCount > 0 {
		logger.Info("Deleted stale alerts", "count", deletedCount)
	}

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
	images, err := centralClient.ListImages(ctx, opts)
	if err != nil {
		return 0, errors.Wrap(err, "failed to list image vulnerabilities from Central")
	}

	logger.Info("Retrieved image vulnerabilities from Central", "count", len(images))

	// Track current image names for cleanup
	currentImageNames := make(map[string]bool)

	// Create/update ImageVulnerability CRDs
	createdCount := 0
	skippedCount := 0
	for _, img := range images {
		crd := central.ConvertImageToCRD(img, exporter.Name)

		// Skip images with no vulnerabilities
		if crd.Status.Summary == nil || crd.Status.Summary.Total == 0 || len(crd.Status.CVEs) == 0 {
			skippedCount++
			continue
		}

		// Track this image's CRD name
		currentImageNames[crd.Name] = true

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

	if skippedCount > 0 {
		logger.Info("Skipped images with no vulnerabilities", "count", skippedCount)
	}
	logger.Info("Synced image vulnerabilities", "created/updated", createdCount)

	// Cleanup stale image vulnerabilities
	deletedCount, err := r.cleanupStaleImageVulnerabilities(ctx, exporter, currentImageNames)
	if err != nil {
		logger.Error(err, "Failed to cleanup stale image vulnerabilities")
		// Don't fail the sync, just log the error
	}
	if deletedCount > 0 {
		logger.Info("Deleted stale image vulnerabilities", "count", deletedCount)
	}

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

	// Track current node names for cleanup
	currentNodeNames := make(map[string]bool)

	// Create/update NodeVulnerability CRDs
	createdCount := 0
	for _, node := range nodes {
		crd := central.ConvertNodeToCRD(node, exporter.Name)
		// Track this node's CRD name
		currentNodeNames[crd.Name] = true

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

	// Cleanup stale node vulnerabilities
	deletedCount, err := r.cleanupStaleNodeVulnerabilities(ctx, exporter, currentNodeNames)
	if err != nil {
		logger.Error(err, "Failed to cleanup stale node vulnerabilities")
		// Don't fail the sync, just log the error
	}
	if deletedCount > 0 {
		logger.Info("Deleted stale node vulnerabilities", "count", deletedCount)
	}

	return createdCount, nil
}

// cleanupAllManagedResources deletes all resources managed by this exporter
func (r *ResultsExporterReconciler) cleanupAllManagedResources(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter) error {
	logger := log.FromContext(ctx)
	logger.Info("Cleaning up all managed resources")

	labelSelector := client.MatchingLabels{
		"results.stackrox.io/exporter": exporter.Name,
	}

	// Delete all Alert resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.Alert{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete Alert resources")
	}

	// Delete all ClusterAlert resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.ClusterAlert{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete ClusterAlert resources")
	}

	// Delete all ImageVulnerability resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.ImageVulnerability{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete ImageVulnerability resources")
	}

	// Delete all NodeVulnerability resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.NodeVulnerability{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete NodeVulnerability resources")
	}

	// Delete all SecurityResults resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.SecurityResults{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete SecurityResults resources")
	}

	// Delete all ClusterSecurityResults resources
	if err := r.DeleteAllOf(ctx, &securityv1alpha1.ClusterSecurityResults{}, labelSelector); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete ClusterSecurityResults resources")
	}

	logger.Info("Completed cleanup of all managed resources")
	return nil
}

// cleanupStaleAlerts removes Alert and ClusterAlert resources no longer present in Central
func (r *ResultsExporterReconciler) cleanupStaleAlerts(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, currentAlertIDs map[string]bool) (int, error) {
	logger := log.FromContext(ctx)
	deletedCount := 0

	// Cleanup namespace-scoped Alerts
	alertList := &securityv1alpha1.AlertList{}
	if err := r.List(ctx, alertList, client.MatchingLabels{
		"results.stackrox.io/exporter": exporter.Name,
	}); err != nil {
		return 0, errors.Wrap(err, "failed to list existing Alerts")
	}

	for i := range alertList.Items {
		alert := &alertList.Items[i]
		alertID := alert.Labels["stackrox.io/alert-id"]
		if alertID != "" && !currentAlertIDs[alertID] {
			logger.V(1).Info("Deleting stale Alert", "name", alert.Name, "namespace", alert.Namespace)
			if err := r.Delete(ctx, alert); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete stale Alert", "name", alert.Name)
			} else {
				deletedCount++
			}
		}
	}

	// Cleanup cluster-scoped ClusterAlerts
	clusterAlertList := &securityv1alpha1.ClusterAlertList{}
	if err := r.List(ctx, clusterAlertList, client.MatchingLabels{
		"results.stackrox.io/exporter": exporter.Name,
	}); err != nil {
		return deletedCount, errors.Wrap(err, "failed to list existing ClusterAlerts")
	}

	for i := range clusterAlertList.Items {
		alert := &clusterAlertList.Items[i]
		alertID := alert.Labels["stackrox.io/alert-id"]
		if alertID != "" && !currentAlertIDs[alertID] {
			logger.V(1).Info("Deleting stale ClusterAlert", "name", alert.Name)
			if err := r.Delete(ctx, alert); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete stale ClusterAlert", "name", alert.Name)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		logger.Info("Cleaned up stale alerts", "deletedCount", deletedCount)
	}
	return deletedCount, nil
}

// cleanupStaleImageVulnerabilities removes ImageVulnerability resources no longer present in Central
func (r *ResultsExporterReconciler) cleanupStaleImageVulnerabilities(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, currentImageNames map[string]bool) (int, error) {
	logger := log.FromContext(ctx)
	deletedCount := 0

	vulnList := &securityv1alpha1.ImageVulnerabilityList{}
	if err := r.List(ctx, vulnList, client.MatchingLabels{
		"results.stackrox.io/exporter": exporter.Name,
	}); err != nil {
		return 0, errors.Wrap(err, "failed to list existing ImageVulnerabilities")
	}

	for i := range vulnList.Items {
		vuln := &vulnList.Items[i]
		// Use the resource name as the identifier
		if !currentImageNames[vuln.Name] {
			logger.V(1).Info("Deleting stale ImageVulnerability", "name", vuln.Name)
			if err := r.Delete(ctx, vuln); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete stale ImageVulnerability", "name", vuln.Name)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		logger.Info("Cleaned up stale image vulnerabilities", "deletedCount", deletedCount)
	}
	return deletedCount, nil
}

// cleanupStaleNodeVulnerabilities removes NodeVulnerability resources no longer present in Central
func (r *ResultsExporterReconciler) cleanupStaleNodeVulnerabilities(ctx context.Context, exporter *resultsv1alpha1.ResultsExporter, currentNodeNames map[string]bool) (int, error) {
	logger := log.FromContext(ctx)
	deletedCount := 0

	vulnList := &securityv1alpha1.NodeVulnerabilityList{}
	if err := r.List(ctx, vulnList, client.MatchingLabels{
		"results.stackrox.io/exporter": exporter.Name,
	}); err != nil {
		return 0, errors.Wrap(err, "failed to list existing NodeVulnerabilities")
	}

	for i := range vulnList.Items {
		vuln := &vulnList.Items[i]
		// Use the resource name as the identifier
		if !currentNodeNames[vuln.Name] {
			logger.V(1).Info("Deleting stale NodeVulnerability", "name", vuln.Name)
			if err := r.Delete(ctx, vuln); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete stale NodeVulnerability", "name", vuln.Name)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		logger.Info("Cleaned up stale node vulnerabilities", "deletedCount", deletedCount)
	}
	return deletedCount, nil
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
		// Watch SecurityResults - reconcile the owning exporter when they change
		Watches(
			&securityv1alpha1.SecurityResults{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecurityResultsToExporter),
		).
		// Watch ClusterSecurityResults - reconcile the owning exporter when they change
		Watches(
			&securityv1alpha1.ClusterSecurityResults{},
			handler.EnqueueRequestsFromMapFunc(r.mapClusterSecurityResultsToExporter),
		).
		Named("resultsexporter").
		Complete(r)
}

// mapSecurityResultsToExporter maps a SecurityResults CR to its owning ResultsExporter
func (r *ResultsExporterReconciler) mapSecurityResultsToExporter(ctx context.Context, obj client.Object) []reconcile.Request {
	sr, ok := obj.(*securityv1alpha1.SecurityResults)
	if !ok {
		return nil
	}

	// Get exporter name from label
	exporterName := sr.Labels["results.stackrox.io/exporter"]
	if exporterName == "" {
		return nil
	}

	// Return reconcile request for the exporter
	// Note: ResultsExporter is cluster-scoped, so namespace is empty
	return []reconcile.Request{
		{
			NamespacedName: client.ObjectKey{
				Name: exporterName,
			},
		},
	}
}

// mapClusterSecurityResultsToExporter maps a ClusterSecurityResults CR to its owning ResultsExporter
func (r *ResultsExporterReconciler) mapClusterSecurityResultsToExporter(ctx context.Context, obj client.Object) []reconcile.Request {
	csr, ok := obj.(*securityv1alpha1.ClusterSecurityResults)
	if !ok {
		return nil
	}

	// Get exporter name from label
	exporterName := csr.Labels["results.stackrox.io/exporter"]
	if exporterName == "" {
		return nil
	}

	// Return reconcile request for the exporter
	// Note: ResultsExporter is cluster-scoped, so namespace is empty
	return []reconcile.Request{
		{
			NamespacedName: client.ObjectKey{
				Name: exporterName,
			},
		},
	}
}
