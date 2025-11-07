# CLAUDE.md

This file provides guidance to Claude Code when working on the StackRox Results Operator.

## Project Overview

The StackRox Results Operator is a Kubernetes operator that exports StackRox/RHACS security data (alerts, vulnerabilities) as native Kubernetes Custom Resources (CRDs). This enables Kubernetes-native access to security posture without requiring direct API calls to Central.

## Development Environment

* **Registry**: quay.io/klape/stackrox-results-operator
* **Kubernetes**: OpenShift cluster (or kind cluster with name `stackrox-all-the-crds`)
* **Operator Namespace**: stackrox-results-operator-system
* **StackRox Central**: https://central.stackrox.svc:443

## Build-Deploy-Test Loop

### 1. Make Code Changes

Edit files in:
* `api/` - CRD type definitions
* `internal/controller/` - Controller logic
* `pkg/central/` - StackRox Central API client

### 2. Build the Operator Image

```bash
# Increment version number (e.g., v10 -> v11)
export VERSION=v11
make docker-build IMG=quay.io/klape/stackrox-results-operator:${VERSION}
```

This uses podman to build the multi-stage Dockerfile.

### 3. Push to Quay.io

```bash
podman push quay.io/klape/stackrox-results-operator:${VERSION}
```

**Note**: Ensure you're authenticated to quay.io first with `podman login quay.io`

### 4. Update the Deployment

```bash
# Update the operator deployment to use new image
kubectl set image deployment/stackrox-results-operator-controller-manager \
  manager=quay.io/klape/stackrox-results-operator:${VERSION} \
  -n stackrox-results-operator-system

# Wait for rollout to complete
kubectl rollout status deployment/stackrox-results-operator-controller-manager \
  -n stackrox-results-operator-system
```

### 5. Trigger Resync (Optional)

If you need to force the operator to recreate all CRDs with the new logic:

```bash
# Delete all alerts to trigger fresh sync
kubectl delete alerts -A --all
kubectl delete clusteralerts --all

# Delete all image vulnerabilities
kubectl delete imagevulnerabilities --all

# Or trigger by updating the ResultsExporter (bumps generation)
kubectl annotate resultsexporter stackrox-exporter force-sync="$(date +%s)"
```

### 6. Verify Results

```bash
# Check operator logs
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  -f

# Check ResultsExporter status
kubectl get resultsexporter stackrox-exporter -o yaml

# Check exported resources
kubectl get alerts -A
kubectl get clusteralerts
kubectl get imagevulnerabilities
kubectl get nodevulnerabilities

# Check counts
echo "Alerts: $(kubectl get alerts -A --no-headers | wc -l)"
echo "ClusterAlerts: $(kubectl get clusteralerts --no-headers | wc -l)"
echo "ImageVulnerabilities: $(kubectl get imagevulnerabilities --no-headers | wc -l)"

# Inspect specific resource
kubectl get alert <name> -n <namespace> -o yaml
```

## Quick Build-Deploy Script

For rapid iteration, you can use this one-liner:

```bash
export VERSION=v$(date +%s) && \
make docker-build IMG=quay.io/klape/stackrox-results-operator:${VERSION} && \
podman push quay.io/klape/stackrox-results-operator:${VERSION} && \
kubectl set image deployment/stackrox-results-operator-controller-manager \
  manager=quay.io/klape/stackrox-results-operator:${VERSION} \
  -n stackrox-results-operator-system && \
kubectl rollout status deployment/stackrox-results-operator-controller-manager \
  -n stackrox-results-operator-system && \
echo "Deployed version: ${VERSION}"
```

## Testing Changes

### Test Alert Syncing

```bash
# Check if alerts are being created
kubectl get alerts -A --no-headers | head -5

# Check alert distribution by namespace
kubectl get alerts -A --no-headers | awk '{print $1}' | sort | uniq -c | sort -rn

# Verify alert has correct entity data
kubectl get alert <name> -n <namespace> -o jsonpath='{.spec.entity}' | jq
```

### Test Image Vulnerability Syncing

```bash
# Check image vulnerabilities
kubectl get imagevulnerabilities --no-headers | head -5

# Check vulnerability counts
kubectl get imagevulnerability <name> -o jsonpath='{.status.summary}' | jq
```

### Test StackRox Central Connection

```bash
# Check operator can connect to Central
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  | grep "Connected to Central"

# Check for sync errors
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  | grep -i error
```

## Common Development Tasks

### Update CRD Definitions

When you modify CRD types in `api/`:

```bash
# Regenerate CRD manifests
make manifests

# Apply updated CRDs (for non-breaking changes)
make install

# For breaking changes (e.g., scope change), delete and recreate:
kubectl delete crd alerts.security.stackrox.io
kubectl apply -f config/crd/bases/security.stackrox.io_alerts.yaml
```

### Debug Controller Issues

```bash
# Watch operator logs in real-time
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  -f

# Check controller reconciliation
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  | grep "Reconciling ResultsExporter"

# Check if controller is running
kubectl get pods -n stackrox-results-operator-system
```

### Test API Client Changes

When modifying `pkg/central/` API client code:

```bash
# Build and deploy as usual
# Then test specific API endpoints

# Check alert fetching
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  | grep "Retrieved alerts from Central"

# Check image vulnerability fetching
kubectl logs -n stackrox-results-operator-system \
  deployment/stackrox-results-operator-controller-manager \
  | grep "Retrieved image vulnerabilities"
```

## Project Structure

```
.
├── api/
│   ├── results/v1alpha1/          # ResultsExporter CRD
│   └── security/v1alpha1/         # Alert, ClusterAlert, ImageVulnerability, etc.
├── cmd/
│   └── main.go                    # Operator entrypoint
├── config/
│   ├── crd/bases/                 # Generated CRD manifests
│   ├── manager/                   # Operator deployment manifests
│   └── rbac/                      # RBAC manifests
├── internal/
│   └── controller/                # Controller reconciliation logic
├── pkg/
│   └── central/                   # StackRox Central API client
│       ├── alerts.go              # Alert API client
│       ├── images.go              # Image vulnerability API client
│       ├── nodes.go               # Node vulnerability API client
│       └── client.go              # Base HTTP client
├── Dockerfile                     # Multi-stage container build
├── Makefile                       # Build targets
└── README.md                      # User documentation
```

## Key Files and Their Purpose

* **`api/security/v1alpha1/alert_types.go`** - Alert CRD (namespace-scoped)
* **`api/security/v1alpha1/clusteralert_types.go`** - ClusterAlert CRD (cluster-scoped)
* **`api/security/v1alpha1/imagevulnerability_types.go`** - ImageVulnerability CRD
* **`api/results/v1alpha1/resultsexporter_types.go`** - Configuration CRD (cluster-scoped)
* **`internal/controller/resultsexporter_controller.go`** - Main controller with sync logic
* **`pkg/central/alerts.go`** - StackRox alerts API client and CRD conversion
* **`pkg/central/images.go`** - StackRox image vulnerabilities API client

## StackRox Central API Details

The operator uses these StackRox Central API endpoints:

* **`GET /v1/alerts`** - List alerts with filtering
  * Returns: `{alerts: [...]}`
  * List format has deployment/namespace at top level
* **`GET /v1/alerts/{id}`** - Get single alert details
  * Returns: Single alert object
  * Detail format has deployment/namespace in `entity` field
* **`GET /v1/images`** - List container images with vulnerabilities
  * Returns: `{images: [...]}`
* **`GET /v1/nodes`** - List Kubernetes nodes with vulnerabilities
  * Returns: `{nodes: [...]}`

**Important**: The list and detail endpoints have different JSON structures. The Alert struct supports both formats.

## Common Gotchas

1. **CRD Scope is Immutable**: You cannot change a CRD from namespace-scoped to cluster-scoped (or vice versa) with `kubectl apply`. You must delete and recreate the CRD.

2. **ResultsExporter is Cluster-Scoped**: Only one ResultsExporter per cluster. It specifies where the auth secret lives via `authSecretNamespace`.

3. **Alert vs ClusterAlert**: Alerts with namespace information go in namespace-scoped `Alert` CRDs. Only alerts without namespace go in `ClusterAlert` CRDs.

4. **API Response Format Differences**: `/v1/alerts` (list) and `/v1/alerts/{id}` (detail) return different JSON structures. The code handles both.

5. **Image Pushing Requires Auth**: Must be logged in to quay.io with `podman login quay.io` before pushing.

6. **Operator Caching**: Sometimes you need to delete existing CRDs to see changes take effect, as the operator may not update existing resources.

## Committing Changes

* Commit after each logical change (e.g., fix one issue, add one feature)
* Use descriptive commit messages explaining what changed and why
* Include the Claude Code footer:
  ```
  🤖 Generated with [Claude Code](https://claude.com/claude-code)

  Co-Authored-By: Claude <noreply@anthropic.com>
  ```

## References

* **README.md** - User-facing documentation with examples
* **StackRox API Docs** - https://docs.openshift.com/acs/rest_api/
* **Kubebuilder Docs** - https://book.kubebuilder.io/ (operator framework used)
