# Sample Manifests

This directory contains sample manifests for the StackRox Results Operator.

## ResultsExporter Configurations

Choose one of these configurations based on your needs:

### Individual Mode (Recommended for < 1000 workloads)

**File:** `resultsexporter-individual-mode.yaml`

Creates one CRD per security finding for better UX:

* One `Alert` per policy violation
* One `ImageVulnerability` per container image
* One `NodeVulnerability` per node

**Deploy:**

```bash
kubectl apply -f central-auth-secret.yaml
kubectl apply -f resultsexporter-individual-mode.yaml
```

**Query:**

```bash
kubectl get alerts --all-namespaces
kubectl get imagevulnerabilities
kubectl get nodevulnerabilities
```

### Aggregated Mode (Recommended for > 1000 workloads)

**File:** `resultsexporter-aggregated-mode.yaml`

Creates one CRD per namespace aggregating all findings for better scalability:

* One `SecurityResults` per namespace (containing ALL alerts and image vulnerabilities)
* One `ClusterSecurityResults` per cluster (containing ALL node vulnerabilities)

**Deploy:**

```bash
kubectl apply -f central-auth-secret.yaml
kubectl apply -f resultsexporter-aggregated-mode.yaml
```

**Query:**

```bash
kubectl get securityresults --all-namespaces
kubectl get clustersecurityresults
```

### Both Modes (For Testing and Comparison)

**File:** `resultsexporter-both-mode.yaml`

Creates **BOTH** individual and aggregated CRDs simultaneously. Perfect for dev preview testing!

**Deploy:**

```bash
kubectl apply -f central-auth-secret.yaml
kubectl apply -f resultsexporter-both-mode.yaml
```

**Compare both approaches:**

```bash
# Individual mode
kubectl get alerts -n production
kubectl describe alert alert-name -n production

# Aggregated mode
kubectl get securityresults -n production
kubectl get securityresults production-results -o yaml
```

Then tell us which you prefer: https://github.com/kylape/stackrox-results-operator/issues

## Authentication Secret

**File:** `central-auth-secret.yaml`

Contains examples for both authentication methods:

1. API Token (recommended for production)
2. Username/Password (htpasswd)

Edit this file to add your credentials before deploying.

## Example Exported CRDs

These files show what the operator creates (users don't create these directly):

### Individual Mode Examples

* **`example-alert.yaml`** - Example `Alert` CRD showing a runtime policy violation
* **`example-imagevulnerability.yaml`** - Example `ImageVulnerability` CRD with CVE details

### Aggregated Mode Examples

* **`example-securityresults.yaml`** - Example `SecurityResults` CRD aggregating all namespace findings

These examples help you understand:

* What data the operator exports
* How to query the exported CRDs
* What fields are available for monitoring/policy enforcement

## Quick Start

1. **Install the operator and CRDs:**

```bash
# From repository root
make install
make deploy IMG=<your-registry>/stackrox-results-operator:tag
```

2. **Create authentication secret:**

```bash
# Edit to add your credentials
vim central-auth-secret.yaml

# Apply
kubectl apply -f central-auth-secret.yaml
```

3. **Choose your mode and deploy ResultsExporter:**

```bash
# For small clusters (better UX)
kubectl apply -f resultsexporter-individual-mode.yaml

# For large clusters (better scale)
kubectl apply -f resultsexporter-aggregated-mode.yaml

# For testing both (give us feedback!)
kubectl apply -f resultsexporter-both-mode.yaml
```

4. **Verify it's working:**

```bash
# Check ResultsExporter status
kubectl get resultsexporter -A

# Check exported resources (individual mode)
kubectl get alerts --all-namespaces
kubectl get imagevulnerabilities

# Check exported resources (aggregated mode)
kubectl get securityresults --all-namespaces
kubectl get clustersecurityresults
```

## Customizing Configuration

All ResultsExporter samples include inline comments explaining each field. Common customizations:

### Change Sync Frequency

```yaml
spec:
  syncInterval: 10m  # Sync every 10 minutes instead of 5
```

### Adjust Severity Filters

```yaml
spec:
  exports:
    alerts:
      filters:
        minSeverity: CRITICAL  # Only CRITICAL (vs HIGH, MEDIUM, LOW)
```

### Limit Resource Counts

```yaml
spec:
  exports:
    alerts:
      maxPerNamespace: 500  # Limit to 500 alerts per namespace
    imageVulnerabilities:
      maxImages: 1000       # Limit to 1000 images total
```

### Filter by Fixability

```yaml
spec:
  exports:
    imageVulnerabilities:
      filters:
        fixableOnly: true   # Only export fixable CVEs
```

## Troubleshooting

### Check Operator Logs

```bash
kubectl logs -n stackrox-operator deployment/stackrox-results-operator-controller-manager
```

### Check ResultsExporter Status

```bash
kubectl get resultsexporter stackrox-exporter-individual -o yaml
```

Look for status conditions indicating connectivity, sync progress, or errors.

### Verify Central Connectivity

```bash
# Test from operator pod
kubectl exec -n stackrox-operator deployment/stackrox-results-operator-controller-manager -- \
  curl -k -H "Authorization: Bearer $(kubectl get secret central-auth -o jsonpath='{.data.token}' | base64 -d)" \
  https://central.stackrox.svc:443/v1/ping
```

## Further Documentation

See the main README.md for:

* Complete API reference
* Use cases and examples
* Pattern comparison
* Development guide
