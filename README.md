# StackRox Results Operator

**Developer Preview - v1alpha1**

A Kubernetes operator that exports StackRox/RHACS security data (alerts, vulnerabilities) as native Kubernetes Custom Resources (CRDs). This enables Kubernetes-native access to your security posture without requiring direct API calls to Central.

## Overview

The StackRox Results Operator provides a Kubernetes-native interface to your security data by:

* Syncing security findings from StackRox Central to Kubernetes CRDs
* Supporting two CRD patterns: individual resources and aggregated resources
* Enabling `kubectl` access to alerts and vulnerabilities
* Facilitating GitOps workflows, monitoring, and policy enforcement

**Important**: This is a developer preview project to explore different approaches to representing security data in Kubernetes. We're testing which pattern users prefer.

## Architecture: Two CRD Patterns

This operator supports **two different patterns** for representing security data. You can choose one, or run both simultaneously to compare.

### Pattern 1: Individual CRDs (Better UX)

Creates one CRD per security finding:

* `Alert` - One per namespace-scoped policy violation (e.g., deployment violations)
* `ClusterAlert` - One per cluster-scoped policy violation (e.g., cluster config violations)
* `ImageVulnerability` - One per container image
* `NodeVulnerability` - One per Kubernetes node

**Pros:**
* Intuitive Kubernetes-native UX
* Simple `kubectl` commands: `kubectl get alerts`, `kubectl get imagevulnerabilities`
* Each resource is independently addressable
* Natural fit for GitOps workflows

**Cons:**
* Doesn't scale well on large clusters (could create thousands of CRDs)
* Higher etcd pressure
* More API server overhead

**Example:**
```bash
$ kubectl get alerts -n production
NAME                                    POLICY                          SEVERITY   STATE
alert-ubuntu-pkg-manager-exec-abc123   Ubuntu Package Manager Execution CRITICAL   ACTIVE
alert-curl-binary-detected-def456      Curl Binary Detected            HIGH       ACTIVE

$ kubectl get clusteralerts
NAME                                            POLICY                                   SEVERITY   STATE
alert-fixable-severity-at-least-impo-4a7021ea  Fixable Severity at least Important      HIGH       ACTIVE
alert-privileged-containers-with-imp-39fc1c10  Privileged Containers with Important CVEs HIGH       ACTIVE

$ kubectl get imagevulnerabilities
NAME                                    IMAGE                         CRITICAL   HIGH   TOTAL
nginx-1-25-3-sha256-abc123             nginx:1.25.3                  3          12     45
redis-7-2-sha256-def456                redis:7.2                     0          5      23
```

### Pattern 2: Aggregated CRDs (Better Scale)

Creates one CRD per namespace/cluster aggregating all findings:

* `SecurityResults` - One per namespace with ALL alerts and image vulnerabilities
* `ClusterSecurityResults` - One per cluster with ALL node vulnerabilities

**Pros:**
* Scales to large clusters (50 CRDs instead of 5000)
* Lower etcd and API server overhead
* Better for high-level dashboards and summaries

**Cons:**
* Less intuitive UX
* Requires `jq` or similar tools to extract specific findings
* Not as natural for GitOps workflows

**Example:**
```bash
$ kubectl get securityresults -n production
NAME                 CRITICAL ALERTS   HIGH ALERTS   TOTAL ALERTS   CRITICAL CVES   TOTAL CVES
production-results   5                 12            23             45              234

# Extract specific alerts requires jq
$ kubectl get securityresults production-results -o json | jq '.spec.alerts[] | select(.policySeverity=="CRITICAL")'
```

### Which Pattern Should I Use?

**For small to medium clusters (< 1000 workloads):** Use `individual` mode for better UX

**For large clusters (> 1000 workloads):** Use `aggregated` mode for better scale

**For dev preview testing:** Use `both` mode and tell us which you prefer!

## Quick Start

### Prerequisites

* Kubernetes cluster v1.11.3+
* StackRox Central deployed and accessible
* kubectl v1.11.3+
* go version v1.24.0+ (for development)

### Installation

1. Install the CRDs:

```bash
kubectl apply -f config/crd/bases/
```

2. Deploy the operator:

```bash
kubectl apply -f config/manager/manager.yaml
```

3. Create a secret with Central credentials:

```bash
# Create the secret in your desired namespace (e.g., stackrox-operator)
# Using API token
kubectl create secret generic central-auth \
  -n stackrox-operator \
  --from-literal=token='your-api-token'

# OR using htpasswd
kubectl create secret generic central-auth \
  -n stackrox-operator \
  --from-literal=username='admin' \
  --from-literal=password='your-password'
```

4. Create a `ResultsExporter` resource (cluster-scoped):

```yaml
apiVersion: results.stackrox.io/v1alpha1
kind: ResultsExporter
metadata:
  name: stackrox-exporter
spec:
  central:
    endpoint: https://central.stackrox.svc:443
    authSecretName: central-auth
    authSecretNamespace: stackrox-operator  # Namespace where the secret is located
    tlsConfig:
      insecureSkipVerify: false  # Set to true for self-signed certs in dev

  exports:
    # Choose: individual, aggregated, or both
    mode: individual

    alerts:
      enabled: true
      filters:
        minSeverity: HIGH
        excludeResolved: true
      maxPerNamespace: 1000

    imageVulnerabilities:
      enabled: true
      filters:
        minSeverity: CRITICAL
        fixableOnly: true
        maxCVEsPerResource: 50
      maxImages: 5000

    nodeVulnerabilities:
      enabled: true
      filters:
        minSeverity: HIGH
        fixableOnly: false
        maxCVEsPerResource: 50

  syncInterval: 5m
  backfillDuration: 720h  # 30 days
```

5. Verify deployment:

```bash
# Check operator status
kubectl get resultsexporter stackrox-exporter -o yaml

# Check exported resources (individual mode)
kubectl get alerts --all-namespaces
kubectl get clusteralerts
kubectl get imagevulnerabilities
kubectl get nodevulnerabilities

# Check exported resources (aggregated mode)
kubectl get securityresults --all-namespaces
kubectl get clustersecurityresults
```

## Configuration Reference

### ResultsExporter Spec

| Field | Type | Description |
|-------|------|-------------|
| `central` | `CentralConfig` | Connection to StackRox Central |
| `exports` | `ExportConfig` | What data to export |
| `syncInterval` | `Duration` | How often to sync (default: 5m) |
| `backfillDuration` | `Duration` | How far back to backfill initially (default: 720h) |

### Export Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `individual` | One CRD per alert/image/node | Small clusters, better UX |
| `aggregated` | One CRD per namespace/cluster | Large clusters, better scale |
| `both` | Create both patterns | Testing/comparison |

### Alert Filters

```yaml
alerts:
  enabled: true
  filters:
    minSeverity: HIGH              # LOW, MEDIUM, HIGH, CRITICAL
    lifecycleStages:               # Optional: filter by stage
      - DEPLOY
      - RUNTIME
    excludeResolved: true          # Skip resolved alerts
  maxPerNamespace: 1000            # Prevent runaway growth
```

### Vulnerability Filters

```yaml
imageVulnerabilities:
  enabled: true
  filters:
    minSeverity: CRITICAL          # LOW, MEDIUM, HIGH, CRITICAL
    fixableOnly: true              # Only include fixable CVEs
    maxCVEsPerResource: 50         # Limit CVEs per image
  maxImages: 5000                  # Max images to export
```

## kubectl Command Examples

### Individual Mode Commands

```bash
# List all namespace-scoped alerts
kubectl get alerts --all-namespaces

# Get alerts in specific namespace
kubectl get alerts -n production

# Show alert details
kubectl describe alert alert-name -n production

# Filter by labels (alerts include severity labels)
kubectl get alerts -l severity=CRITICAL

# Watch for new alerts
kubectl get alerts -n production -w

# List all cluster-scoped alerts (alerts without a namespace)
kubectl get clusteralerts

# Show cluster alert details
kubectl describe clusteralert alert-fixable-severity-at-least-impo-4a7021ea

# Filter cluster alerts by severity
kubectl get clusteralerts -l stackrox.io/severity=HIGH

# Watch for new cluster alerts
kubectl get clusteralerts -w

# List image vulnerabilities
kubectl get imagevulnerabilities

# Show vulnerabilities for specific image
kubectl get imagevulnerability nginx-1-25-3-sha256-abc123 -o yaml

# List node vulnerabilities
kubectl get nodevulnerabilities

# Show critical node vulnerabilities
kubectl get nodevulnerabilities -l severity=CRITICAL
```

### Aggregated Mode Commands

```bash
# Get security summary for namespace
kubectl get securityresults -n production

# View all findings in namespace
kubectl get securityresults production-results -o yaml

# Extract critical alerts using jq
kubectl get securityresults production-results -n production -o json \
  | jq '.spec.alerts[] | select(.policySeverity=="CRITICAL")'

# Get cluster-wide node vulnerability summary
kubectl get clustersecurityresults

# View all node vulnerabilities
kubectl get clustersecurityresults cluster-results -o yaml

# Count total CVEs across cluster
kubectl get clustersecurityresults cluster-results -o json \
  | jq '.status.summary.totalCVEs'
```

## Use Cases

### 1. GitOps Workflows

Export security findings to Git for audit trails and policy enforcement:

```bash
# Export current state
kubectl get alerts -n production -o yaml > production-alerts.yaml
kubectl get clusteralerts -o yaml > cluster-alerts.yaml
kubectl get imagevulnerabilities -o yaml > image-vulns.yaml

# Commit to Git for tracking
git add production-alerts.yaml cluster-alerts.yaml image-vulns.yaml
git commit -m "Security snapshot $(date)"
```

### 2. Monitoring and Alerting

Use Kubernetes monitoring tools to alert on security findings:

```yaml
# Prometheus-style alert
- alert: CriticalSecurityAlert
  expr: count(kube_customresource_alert{severity="CRITICAL"}) > 0
  annotations:
    summary: "Critical security alerts detected"
```

### 3. Policy Enforcement

Use admission controllers or policy engines:

```yaml
# Example: Kyverno policy blocking deployments with critical vulnerabilities
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-critical-vulns
spec:
  validationFailureAction: enforce
  rules:
    - name: check-image-vulns
      match:
        resources:
          kinds:
            - Deployment
      validate:
        message: "Image has critical vulnerabilities"
        deny:
          conditions:
            - key: "{{ request.object.spec.template.spec.containers[].image }}"
              operator: In
              value: "{{ query.imagevulnerabilities.*.spec.image.fullName[?status.summary.critical.total > `0`] }}"
```

### 4. Dashboard Integration

Build custom dashboards querying CRDs:

```bash
# Get metrics for dashboard
kubectl get securityresults -A -o json \
  | jq '[.items[] | {
      namespace: .metadata.namespace,
      criticalAlerts: .status.summary.criticalAlerts,
      criticalCVEs: .status.summary.criticalCVEs
    }]'
```

## API Reference

### Individual CRDs (security.stackrox.io/v1alpha1)

* **Alert** (namespaced): Namespace-scoped policy violations (e.g., deployment violations)
* **ClusterAlert** (cluster-scoped): Cluster-scoped policy violations (e.g., cluster configuration issues)
* **ImageVulnerability** (cluster-scoped): Container image vulnerabilities
* **NodeVulnerability** (cluster-scoped): Kubernetes node vulnerabilities

### Aggregated CRDs (security.stackrox.io/v1alpha1)

* **SecurityResults** (namespaced): All security findings for a namespace
* **ClusterSecurityResults** (cluster-scoped): All node vulnerabilities cluster-wide

### Configuration CRD (results.stackrox.io/v1alpha1)

* **ResultsExporter** (cluster-scoped): Operator configuration - one per cluster

**Why cluster-scoped?** ResultsExporter is cluster-scoped because:
* There's typically one StackRox Central instance per cluster
* Most output CRDs are cluster-scoped (ClusterAlert, ImageVulnerability, NodeVulnerability)
* Prevents confusion from multiple conflicting configurations
* Matches the deployment model (one operator instance per cluster)

See `/api` directory for complete type definitions.

## Development

### Building from Source

```bash
# Build the operator binary
make build

# Run locally (outside cluster)
make run

# Run tests
make test

# Generate/update CRDs
make manifests

# Install CRDs into cluster
make install
```

### Building Container Image

```bash
# Build and push image
make docker-build docker-push IMG=<your-registry>/stackrox-results-operator:tag

# Deploy to cluster
make deploy IMG=<your-registry>/stackrox-results-operator:tag
```

### Testing Both Modes

To compare both patterns:

1. Set `exports.mode: both` in your ResultsExporter
2. Observe both individual and aggregated CRDs being created
3. Try common operations with both patterns
4. Compare UX, performance, and suitability for your use cases
5. **Give us feedback!** (see below)

## Pattern Comparison Table

| Aspect | Individual CRDs | Aggregated CRDs |
|--------|----------------|-----------------|
| **kubectl UX** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐ Requires jq |
| **Scalability** | ⭐⭐ Poor (5000+ CRDs) | ⭐⭐⭐⭐⭐ Excellent (50 CRDs) |
| **GitOps fit** | ⭐⭐⭐⭐⭐ Natural | ⭐⭐⭐ Workable |
| **Discoverability** | ⭐⭐⭐⭐⭐ Each finding addressable | ⭐⭐ Must query arrays |
| **API server load** | ⭐⭐ High | ⭐⭐⭐⭐⭐ Low |
| **etcd pressure** | ⭐⭐ High | ⭐⭐⭐⭐⭐ Low |
| **Real-time updates** | ⭐⭐⭐⭐ Per-finding | ⭐⭐⭐⭐⭐ Batch updates |
| **Monitoring integration** | ⭐⭐⭐⭐⭐ Easy | ⭐⭐⭐ More complex |

## Roadmap

### v1alpha1 (Current - Developer Preview)
- [x] Basic CRD definitions
- [x] Individual CRD pattern
- [x] Aggregated CRD pattern
- [x] Mode selection
- [ ] Central API client
- [ ] Sync controllers
- [ ] Basic filtering

### v1alpha2 (Planned)
- [ ] Webhook validation
- [ ] Status conditions
- [ ] Metrics/observability
- [ ] Advanced filtering
- [ ] Label selectors
- [ ] User feedback integration

### v1beta1 (Future)
- [ ] Production-ready based on user feedback
- [ ] Choose single pattern or support both
- [ ] Performance optimizations
- [ ] HA support
- [ ] Advanced use cases

## Backlog

Features and enhancements being considered for future releases:

### Namespace Filtering
Add configuration to ResultsExporter CRD to selectively include/exclude namespaces from results:

```yaml
spec:
  exports:
    namespaceSelector:
      # Include only these namespaces (if specified)
      include:
        matchLabels:
          environment: production
        matchExpressions:
          - {key: team, operator: In, values: [platform, security]}

      # Exclude these namespaces (applied after include)
      exclude:
        matchLabels:
          monitoring: prometheus
        matchNames:
          - kube-system
          - kube-public

    # How to handle cluster-scoped resources (alerts without namespace)
    clusterScopedResources: include  # include, exclude, or separate
```

Benefits:
* Reduce noise by filtering out non-production namespaces
* Separate production/staging/dev exports
* Exclude system namespaces
* Control what data gets exported to Git

### Open Reports API Integration
Support [OpenReports](https://openreports.io/) format for standardized security reporting:

```yaml
spec:
  exports:
    openReports:
      enabled: true
      format: sarif  # SARIF, CycloneDX, SPDX, etc.
      output:
        - type: kubernetes
          configMapName: security-report
        - type: s3
          bucket: security-reports
          path: /cluster-name/
```

Benefits:
* Standardized report format for tool interoperability
* Integration with CI/CD pipelines
* Compatible with existing security tools
* Multi-format support (SARIF, CycloneDX, SPDX)

## We Need Your Feedback!

This is a **developer preview** to explore different approaches. We need your input:

### Please Tell Us

1. **Which pattern do you prefer?** Individual or Aggregated?
2. **What's your cluster size?** How many workloads/images/nodes?
3. **What's your use case?** Monitoring? GitOps? Policy enforcement?
4. **Which commands do you run most?** What's your workflow?
5. **What's missing?** What features would make this more useful?

### How to Provide Feedback

* **GitHub Issues**: https://github.com/kylape/stackrox-results-operator/issues
* **Preferred Pattern**: Tell us which mode you're using and why
* **UX Feedback**: Share your kubectl workflows and pain points
* **Scale Data**: Share cluster size and performance observations

Your feedback will directly shape whether we:
* Focus on individual CRDs for better UX
* Focus on aggregated CRDs for better scale
* Support both patterns long-term
* Explore hybrid approaches

## License

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
