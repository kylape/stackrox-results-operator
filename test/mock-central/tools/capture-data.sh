#!/bin/bash
# Captures data from real StackRox Central and formats for mock service

set -xeo pipefail

if [ "$#" -lt 3 ]; then
    echo "Error: Missing required arguments"
    echo "Usage: ROX_API_TOKEN=<token> $0 <central-endpoint> <output-dir> <cluster-name>"
    echo ""
    echo "Arguments:"
    echo "  central-endpoint  - StackRox Central API endpoint (e.g., central.stackrox.svc:443)"
    echo "  output-dir        - Directory to save captured data files"
    echo "  cluster-name      - Name of cluster to capture data for (required)"
    echo ""
    echo "Examples:"
    echo "  # Capture data for production cluster"
    echo "  ROX_API_TOKEN=\$token $0 central.stackrox.svc:443 ./data production"
    echo ""
    echo "  # Capture data for staging cluster to different directory"
    echo "  ROX_API_TOKEN=\$token $0 central.stackrox.svc:443 ./data-staging staging"
    exit 1
fi

API_ENDPOINT="$1"
OUTPUT_DIR="$2"
CLUSTER_NAME="$3"
ROX_API_TOKEN="${ROX_API_TOKEN:-$(cat /root/workspace/sessions/results-operator/admin-password.txt 2>/dev/null || echo '')}"

if [ -z "$ROX_API_TOKEN" ]; then
    echo "Error: ROX_API_TOKEN environment variable not set and admin-password.txt not found"
    echo "Set the token with: export ROX_API_TOKEN=<your-token>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "======================================"
echo "Capturing data from Central"
echo "======================================"
echo "Endpoint: $API_ENDPOINT"
echo "Output:   $OUTPUT_DIR"
echo "Cluster:  $CLUSTER_NAME"
echo ""

# URL-encode the cluster filter query (used for alerts and images)
QUERY="Cluster:$CLUSTER_NAME"
ENCODED_QUERY=$(printf %s "$QUERY" | jq -sRr @uri)

# # Capture alerts
# echo "[1/4] Fetching alerts for cluster '$CLUSTER_NAME'..."
# curl -k -H "Authorization: Bearer $ROX_API_TOKEN" \
#   "https://$API_ENDPOINT/v1/alerts?query=$ENCODED_QUERY" \
#   > "$OUTPUT_DIR/alerts.json"
# ALERT_COUNT=$(jq '.alerts | length' "$OUTPUT_DIR/alerts.json" 2>/dev/null || echo "0")
# echo "      Retrieved $ALERT_COUNT alerts"

# # Capture images (NDJSON)
# echo "[2/5] Fetching images for cluster '$CLUSTER_NAME' (this may take a while)..."
# curl -k -s -H "Authorization: Bearer $ROX_API_TOKEN" \
#   "https://$API_ENDPOINT/v1/export/images?query=$ENCODED_QUERY" \
#   > "$OUTPUT_DIR/images.ndjson"
# IMAGE_COUNT=$(wc -l < "$OUTPUT_DIR/images.ndjson" | tr -d ' ')
# echo "      Retrieved $IMAGE_COUNT images"

# Capture deployments
echo "[3/5] Fetching deployments for cluster '$CLUSTER_NAME'..."
curl -k -s -H "Authorization: Bearer $ROX_API_TOKEN" \
  "https://$API_ENDPOINT/v1/deployments?query=$ENCODED_QUERY" \
  > "$OUTPUT_DIR/deployments.json"
DEPLOYMENT_COUNT=$(jq '.deployments | length' "$OUTPUT_DIR/deployments.json" 2>/dev/null || echo "0")
echo "      Retrieved $DEPLOYMENT_COUNT deployments"

# Capture clusters
echo "[4/5] Fetching cluster metadata..."
curl -k -s -H "Authorization: Bearer $ROX_API_TOKEN" \
  "https://$API_ENDPOINT/v1/clusters" \
  | jq --arg filter "$CLUSTER_NAME" '{clusters: [.clusters[] | select(.name == $filter)]}' \
  > "$OUTPUT_DIR/clusters.json"
CLUSTER_COUNT=$(jq '.clusters | length' "$OUTPUT_DIR/clusters.json" 2>/dev/null || echo "0")
echo "      Retrieved $CLUSTER_COUNT cluster(s)"

if [ "$CLUSTER_COUNT" = "0" ]; then
    echo "      Warning: No cluster found with name '$CLUSTER_NAME'"
    echo "      Creating empty nodes.json"
    echo '{"nodes":[]}' > "$OUTPUT_DIR/nodes.json"
    total_nodes=0
else
    # Capture nodes for the cluster
    echo "[5/5] Fetching nodes for cluster '$CLUSTER_NAME'..."

    CLUSTER_ID=$(jq -r '.clusters[0].id' "$OUTPUT_DIR/clusters.json")

    # Fetch nodes for this cluster
    nodes_json=$(curl -k -s -H "Authorization: Bearer $ROX_API_TOKEN" \
        "https://$API_ENDPOINT/v1/nodes/$CLUSTER_ID")

    # Extract nodes array and add clusterId field to each node
    echo "$nodes_json" | jq --arg cid "$CLUSTER_ID" \
        '{nodes: [.nodes[]? | . + {clusterId: $cid}]}' \
        > "$OUTPUT_DIR/nodes.json"

    total_nodes=$(jq '.nodes | length' "$OUTPUT_DIR/nodes.json" 2>/dev/null || echo "0")
    echo "      Retrieved $total_nodes nodes"
fi

echo ""
echo "======================================"
echo "Data capture complete!"
echo "======================================"
echo ""
echo "Summary:"
echo "  Cluster:      $CLUSTER_NAME"
echo "  Alerts:       $ALERT_COUNT"
echo "  Images:       $IMAGE_COUNT"
echo "  Deployments:  ${DEPLOYMENT_COUNT:-0}"
echo "  Nodes:        ${total_nodes:-0}"
echo ""
echo "Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
echo ""
echo "Next steps:"
echo "  1. Review the captured data"
echo "  2. Upload to mock service: ./tools/upload-data.sh"
