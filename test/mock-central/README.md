# Mock StackRox Central Service

A lightweight HTTP mock service that simulates StackRox Central's API endpoints for testing and scale validation of the results-operator.

## Overview

The mock Central service provides:

* **API Compatibility**: Implements the same HTTP endpoints used by results-operator
* **No Authentication**: Simplified for testing (no auth headers required)
* **Data Upload**: Load real Central data via HTTP endpoint
* **Namespace Auto-Creation**: Automatically creates Kubernetes namespaces from alert data
* **NDJSON Streaming**: Properly streams image export data like real Central

## Architecture

```
┌──────────────────┐
│  Real Central    │
│  (Customer)      │
└─────┬────────────┘
      │ capture-data.sh
      ▼
┌──────────────────┐
│  Data Files      │
│  *.json, *.ndjson│
└─────┬────────────┘
      │ upload-data.sh
      ▼
┌──────────────────┐     ┌──────────────────┐
│  Mock Central    │────▶│  Results         │
│  (Pod)           │     │  Operator        │
└──────────────────┘     └──────────────────┘
```

## API Endpoints

### Central API (Read-Only)

* `GET /v1/ping` - Health check
* `GET /v1/alerts` - List all alerts
* `GET /v1/export/images` - Export images (NDJSON stream)
* `GET /v1/clusters` - List clusters
* `GET /v1/nodes/{clusterID}` - List nodes for specific cluster

### Admin API

* `POST /admin/upload` - Upload data files
* `POST /admin/preprocess` - Create namespaces from alerts

## Quick Start

### 1. Capture Data from Real Central

```bash
cd test/mock-central

# Set token (either from admin password or customer token)
export ROX_API_TOKEN=$(cat /root/workspace/sessions/results-operator/admin-password.txt)

# Or for customer Central
export ROX_API_TOKEN="customer-api-token"

# Capture data for a specific cluster (cluster name is required)
./tools/capture-data.sh central.stackrox.svc:443 ./data production

# Capture data for staging cluster to different directory
./tools/capture-data.sh central.stackrox.svc:443 ./data-staging staging
```

This creates four files in the output directory:

* `alerts.json` - Alerts for the specified cluster
* `images.ndjson` - Images deployed in the specified cluster
* `clusters.json` - Metadata for the specified cluster
* `nodes.json` - Nodes in the specified cluster (with clusterId field)

### 2. Build and Deploy Mock Service

```bash
# Build container image
cd /root/workspace/sessions/results-operator/stackrox-results-operator
docker build -t localhost:5001/mock-central:latest -f test/mock-central/Dockerfile .
podman push --tls-verify=false localhost:5001/mock-central:latest

# Deploy to Kubernetes
kubectl apply -f test/mock-central/deploy.yaml

# Verify deployment
kubectl get pods -n stackrox -l app=mock-central
```

### 3. Upload Data to Mock Service

**Note**: The upload script requires connectivity to the Kubernetes cluster. Run this from a pod inside the cluster or use port-forwarding.

**Option A: Port-forward and upload from host**

```bash
# In one terminal
kubectl port-forward -n stackrox svc/mock-central 8443:443

# In another terminal
cd test/mock-central
./tools/upload-data.sh http://localhost:8443 ./data
```

**Option B: Upload from within cluster**

```bash
# Copy data to a pod
kubectl run -n stackrox uploader --image=curlimages/curl -- sleep 3600
kubectl cp ./data stackrox/uploader:/tmp/data
kubectl exec -n stackrox uploader -- sh -c '
  curl -X POST http://mock-central.stackrox.svc:443/admin/upload \
    -F "alerts=@/tmp/data/alerts.json" \
    -F "images=@/tmp/data/images.ndjson" \
    -F "clusters=@/tmp/data/clusters.json" \
    -F "nodes=@/tmp/data/nodes.json"
'
kubectl delete pod -n stackrox uploader
```

This will:

* Upload alerts.json, images.ndjson, clusters.json, nodes.json
* Automatically extract namespaces from alerts
* Create missing namespaces in Kubernetes

### 4. Configure Results Operator

Edit your ResultsExporter CR to point to the mock service:

```yaml
apiVersion: results.stackrox.io/v1alpha1
kind: ResultsExporter
metadata:
  name: exporter
  namespace: stackrox
spec:
  central:
    endpoint: http://mock-central.stackrox.svc:443  # Changed from central.stackrox.svc:443
    # Remove authSecretName - no auth needed for mock
  exports:
    mode: individual
    alerts:
      enabled: true
    imageVulnerabilities:
      enabled: true
    nodeVulnerabilities:
      enabled: true
```

### 5. Verify It Works

```bash
# Test mock API
kubectl run -n stackrox curl-test --rm -i --tty --image=curlimages/curl -- \
  curl http://mock-central.stackrox.svc:443/v1/ping

# Check alerts
kubectl run -n stackrox curl-test --rm -i --tty --image=curlimages/curl -- \
  curl http://mock-central.stackrox.svc:443/v1/alerts

# Watch results operator logs
kubectl logs -n stackrox -l app=results-operator -f
```

## Data Format

### alerts.json

```json
{
  "alerts": [
    {
      "id": "alert-id",
      "policy": {
        "id": "policy-id",
        "name": "Policy Name",
        "severity": "CRITICAL_SEVERITY"
      },
      "deployment": {
        "namespace": "production",
        "name": "nginx"
      }
    }
  ]
}
```

### images.ndjson

Newline-delimited JSON (one object per line):

```json
{"result":{"image":{"name":{"fullName":"nginx:latest"},"scan":{...}}}}
{"result":{"image":{"name":{"fullName":"redis:6"},"scan":{...}}}}
```

### clusters.json

```json
{
  "clusters": [
    {"id": "cluster-1", "name": "prod-cluster"}
  ]
}
```

### nodes.json

All nodes in single file with `clusterId` field:

```json
{
  "nodes": [
    {
      "clusterId": "cluster-1",
      "nodeName": "worker-1",
      "osImage": "Red Hat Enterprise Linux 9.0",
      "cves": [...]
    }
  ]
}
```

## Scale Testing

### Capture Data from Multiple Clusters

The capture script requires a cluster name. To test with data from multiple clusters, capture each cluster to a separate directory and merge:

```bash
export ROX_API_TOKEN="your-token"

# Capture data for each cluster
./tools/capture-data.sh central.stackrox.svc:443 ./data-prod production
./tools/capture-data.sh central.stackrox.svc:443 ./data-staging staging
./tools/capture-data.sh central.stackrox.svc:443 ./data-dev development

# Merge clusters and nodes (alerts and images stay separate)
jq -s '{clusters: [.[].clusters[]] | unique_by(.id)}' \
  ./data-*/clusters.json > ./data-merged/clusters.json

jq -s '{nodes: [.[].nodes[]] | unique_by(.id)}' \
  ./data-*/nodes.json > ./data-merged/nodes.json

# Combine alerts (keep all)
jq -s '{alerts: [.[].alerts[]]}' \
  ./data-*/alerts.json > ./data-merged/alerts.json

# Combine images (keep all lines)
cat ./data-*/images.ndjson > ./data-merged/images.ndjson

# Upload merged data
./tools/upload-data.sh http://mock-central.stackrox.svc:443 ./data-merged
```

### Multiply Data for Scale Tests

```bash
cd test/mock-central/data

# Create 10x alerts
jq '.alerts = ([.alerts[]] * 10)' alerts.json > alerts.json.tmp
mv alerts.json.tmp alerts.json

# Create 10x images (duplicate each line 10 times)
awk '{for(i=0;i<10;i++)print}' images.ndjson > images.ndjson.tmp
mv images.ndjson.tmp images.ndjson

# Re-upload
cd ..
./tools/upload-data.sh http://mock-central.stackrox.svc:443 ./data
```

### Test Scenarios

**Single Cluster Baseline**: Capture and use data from one cluster as-is

```bash
export ROX_API_TOKEN="your-token"
./tools/capture-data.sh customer-central:443 ./data production
./tools/upload-data.sh http://mock-central.stackrox.svc:443 ./data
```

**Multi-Cluster**: Capture and merge data from multiple clusters

```bash
export ROX_API_TOKEN="your-token"
./tools/capture-data.sh customer-central:443 ./data-prod production
./tools/capture-data.sh customer-central:443 ./data-staging staging

# Merge (see "Capture Data from Multiple Clusters" section above)
# ... merge commands ...

./tools/upload-data.sh http://mock-central.stackrox.svc:443 ./data-merged
```

**10x Scale**: Multiply all data 10 times

```bash
cd data
jq '.alerts = ([.alerts[]] * 10)' alerts.json > alerts.json.tmp && mv alerts.json.tmp alerts.json
awk '{for(i=0;i<10;i++)print}' images.ndjson > images.ndjson.tmp && mv images.ndjson.tmp images.ndjson
jq '.nodes = ([.nodes[]] * 10)' nodes.json > nodes.json.tmp && mv nodes.json.tmp nodes.json
cd .. && ./tools/upload-data.sh
```

**100x Scale**: Same as above with 100 multiplier

**Namespace Explosion**: Create synthetic data with 1000+ unique namespaces

```bash
# Generate alerts with unique namespaces
jq '.alerts = [range(1000) | {
  "id": "alert-\(.)",
  "policy": {"name": "Test Policy", "severity": "HIGH_SEVERITY"},
  "deployment": {"namespace": "ns-\(.)"}
}]' data/alerts.json > data/alerts.json.tmp
mv data/alerts.json.tmp data/alerts.json
```

## Troubleshooting

### Data not loading

```bash
# Check pod logs
kubectl logs -n stackrox -l app=mock-central

# Verify files were uploaded
kubectl exec -n stackrox deploy/mock-central -- ls -lh /data

# Re-upload data
./tools/upload-data.sh http://mock-central.stackrox.svc:443 ./data
```

### Namespaces not created

```bash
# Manually trigger preprocessing
curl -X POST http://mock-central.stackrox.svc:443/admin/preprocess

# Check RBAC permissions
kubectl get clusterrolebinding mock-central-namespace-creator

# Check service account
kubectl get sa -n stackrox mock-central
```

### Results operator not connecting

```bash
# Verify service is running
kubectl get svc -n stackrox mock-central

# Test connectivity from operator pod
kubectl exec -n stackrox deploy/results-operator -- \
  curl http://mock-central.stackrox.svc:443/v1/ping

# Check ResultsExporter configuration
kubectl get resultsexporter -o yaml
```

## Development

### Local Testing

```bash
# Run locally (outside Kubernetes)
cd test/mock-central
export DATA_DIR=./data
export PORT=8443
go run main.go

# In another terminal
curl http://localhost:8443/v1/ping

# Upload data locally
./tools/upload-data.sh http://localhost:8443 ./data
```

### Rebuilding

```bash
# Rebuild and redeploy
docker build -t localhost:5001/mock-central:latest -f test/mock-central/Dockerfile .
podman push --tls-verify=false localhost:5001/mock-central:latest
kubectl rollout restart deployment/mock-central -n stackrox
```

## Files

```
test/mock-central/
├── main.go                    # HTTP server
├── handlers/
│   ├── alerts.go              # /v1/alerts
│   ├── images.go              # /v1/export/images (NDJSON)
│   ├── nodes.go               # /v1/clusters, /v1/nodes/{id}
│   ├── ping.go                # /v1/ping
│   └── admin.go               # /admin/upload, /admin/preprocess
├── storage/
│   └── memory.go              # In-memory data storage
├── preprocessor/
│   └── namespace_creator.go   # Namespace creation from alerts
├── tools/
│   ├── capture-data.sh        # Capture from real Central
│   └── upload-data.sh         # Upload to mock service
├── data/                      # NOT checked in (.gitignore)
│   ├── alerts.json
│   ├── images.ndjson
│   ├── clusters.json
│   └── nodes.json
├── Dockerfile                 # Container image
├── deploy.yaml                # Kubernetes manifests
└── README.md                  # This file
```

## Notes

* Data files are NOT checked into git (see `.gitignore`)
* emptyDir volume means data is lost if pod restarts - re-upload after pod restarts
* No authentication - simplified for testing only
* No query filtering - return all data always (filter before upload if needed)
* Designed for scale testing, not production use
