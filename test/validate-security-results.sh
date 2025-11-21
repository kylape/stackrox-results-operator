#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

MOCK_CENTRAL_URL="https://mock-central.stackrox.svc:443"
BASIC_AUTH="Basic $(echo -n 'admin:letmein' | base64)"

echo "=== Validating SecurityResults against Mock Central ==="
echo ""

# Function to query mock Central
query_central() {
    local endpoint="$1"
    kubectl run -n stackrox curl-test-$$ --rm -i --tty --restart=Never --image=curlimages/curl -- \
        curl -k -s -H "Authorization: $BASIC_AUTH" "${MOCK_CENTRAL_URL}${endpoint}" 2>/dev/null || true
}

# 1. Get alerts from Central
echo "📡 Querying alerts from Mock Central..."
CENTRAL_ALERTS=$(query_central "/v1/alerts")
CENTRAL_ALERT_COUNT=$(echo "$CENTRAL_ALERTS" | jq '.alerts | length' 2>/dev/null || echo "0")
echo "   Found $CENTRAL_ALERT_COUNT alerts in Central"

# Group alerts by namespace
CENTRAL_ALERTS_BY_NS=$(echo "$CENTRAL_ALERTS" | jq -r '
    .alerts
    | group_by(
        if .deployment.namespace then .deployment.namespace
        elif .commonEntityInfo.namespace then .commonEntityInfo.namespace
        else "cluster-scoped"
        end
    )
    | map({
        namespace: (if .[0].deployment.namespace then .[0].deployment.namespace
                    elif .[0].commonEntityInfo.namespace then .[0].commonEntityInfo.namespace
                    else "cluster-scoped"
                    end),
        count: length,
        critical: [.[] | select(.policy.severity == "CRITICAL_SEVERITY")] | length,
        high: [.[] | select(.policy.severity == "HIGH_SEVERITY")] | length
    })
' 2>/dev/null || echo "[]")

echo "   Alerts grouped by namespace:"
echo "$CENTRAL_ALERTS_BY_NS" | jq -r '.[] | "     \(.namespace): \(.count) alerts (Critical: \(.critical), High: \(.high))"' | head -20

# 2. Get image vulnerabilities from Central (sample first 100 lines to avoid overwhelming output)
echo ""
echo "📡 Querying images from Mock Central (sampling first 100)..."
CENTRAL_IMAGES=$(query_central "/v1/export/images" | head -100)
CENTRAL_IMAGE_COUNT=$(echo "$CENTRAL_IMAGES" | wc -l)
echo "   Sampled $CENTRAL_IMAGE_COUNT image records from Central"

# Parse a few sample images to understand namespace distribution
SAMPLE_IMAGE_NAMESPACES=$(echo "$CENTRAL_IMAGES" | head -20 | jq -r '.result.image.deployments[].namespace' 2>/dev/null | sort | uniq -c || echo "")
if [ -n "$SAMPLE_IMAGE_NAMESPACES" ]; then
    echo "   Sample namespace distribution from deployments:"
    echo "$SAMPLE_IMAGE_NAMESPACES" | head -10
fi

# 3. Get SecurityResults from Kubernetes
echo ""
echo "🔍 Querying SecurityResults from Kubernetes..."
K8S_SECURITY_RESULTS=$(kubectl get securityresults -A -o json)
K8S_SR_COUNT=$(echo "$K8S_SECURITY_RESULTS" | jq '.items | length')
echo "   Found $K8S_SR_COUNT SecurityResults CRs"

# Analyze SecurityResults
echo ""
echo "=== SecurityResults Analysis ==="
echo "$K8S_SECURITY_RESULTS" | jq -r '
    .items[]
    | {
        namespace: .metadata.namespace,
        alerts: (.status.alerts | length),
        images: (.status.imageVulnerabilities | length),
        totalAlerts: .status.summary.totalAlerts,
        criticalAlerts: .status.summary.criticalAlerts,
        highAlerts: .status.summary.highAlerts,
        totalCVEs: .status.summary.totalCVEs,
        criticalCVEs: .status.summary.criticalCVEs
    }
    | "\(.namespace): \(.alerts) alerts, \(.images) images | Summary: \(.totalAlerts) alerts (\(.criticalAlerts) critical, \(.highAlerts) high), \(.totalCVEs) CVEs (\(.criticalCVEs) critical)"
' | head -20

# 4. Cross-validation: Check if namespaces with alerts in Central have SecurityResults
echo ""
echo "=== Cross-Validation ==="
echo "Checking if namespaces with alerts in Central have corresponding SecurityResults..."

CENTRAL_NS_WITH_ALERTS=$(echo "$CENTRAL_ALERTS_BY_NS" | jq -r '.[] | select(.namespace != "cluster-scoped") | .namespace' 2>/dev/null || echo "")
K8S_SR_NAMESPACES=$(echo "$K8S_SECURITY_RESULTS" | jq -r '.items[].metadata.namespace')

MISSING_COUNT=0
MATCHED_COUNT=0

for ns in $CENTRAL_NS_WITH_ALERTS; do
    if echo "$K8S_SR_NAMESPACES" | grep -q "^${ns}$"; then
        MATCHED_COUNT=$((MATCHED_COUNT + 1))
    else
        # Check if namespace exists in cluster
        if kubectl get namespace "$ns" &>/dev/null; then
            echo -e "  ${RED}✗${NC} Namespace '$ns' has alerts in Central but no SecurityResults CR"
            MISSING_COUNT=$((MISSING_COUNT + 1))
        else
            echo -e "  ${YELLOW}⊘${NC} Namespace '$ns' has alerts in Central but doesn't exist in cluster (expected)"
        fi
    fi
done

echo ""
echo "=== Summary ==="
echo -e "Mock Central:"
echo "  • Total alerts: $CENTRAL_ALERT_COUNT"
echo "  • Namespaces with alerts: $(echo "$CENTRAL_ALERTS_BY_NS" | jq -r 'length')"
echo "  • Sample image records: $CENTRAL_IMAGE_COUNT"
echo ""
echo -e "Kubernetes SecurityResults:"
echo "  • Total SecurityResults CRs: $K8S_SR_COUNT"
echo "  • Matched namespaces: $MATCHED_COUNT"
if [ $MISSING_COUNT -gt 0 ]; then
    echo -e "  ${RED}• Missing SecurityResults: $MISSING_COUNT${NC}"
else
    echo -e "  ${GREEN}• All namespaces with alerts have SecurityResults${NC}"
fi

# 5. Detailed comparison for a few namespaces
echo ""
echo "=== Detailed Validation (First 3 Namespaces) ==="

SAMPLE_NAMESPACES=$(echo "$K8S_SR_NAMESPACES" | head -3)

for ns in $SAMPLE_NAMESPACES; do
    echo ""
    echo "Namespace: $ns"
    echo "----------------------------------------"

    # Get alerts count from Central
    CENTRAL_NS_ALERTS=$(echo "$CENTRAL_ALERTS" | jq --arg ns "$ns" '
        [.alerts[] | select(
            (.deployment.namespace == $ns) or
            (.commonEntityInfo.namespace == $ns)
        )] | length
    ' 2>/dev/null || echo "0")

    # Get alerts count from SecurityResults
    K8S_NS_ALERTS=$(echo "$K8S_SECURITY_RESULTS" | jq --arg ns "$ns" '
        .items[] | select(.metadata.namespace == $ns) | .status.alerts | length
    ' 2>/dev/null || echo "0")

    # Get image count from SecurityResults
    K8S_NS_IMAGES=$(echo "$K8S_SECURITY_RESULTS" | jq --arg ns "$ns" '
        .items[] | select(.metadata.namespace == $ns) | .status.imageVulnerabilities | length
    ' 2>/dev/null || echo "0")

    # Get summary from SecurityResults
    K8S_SUMMARY=$(echo "$K8S_SECURITY_RESULTS" | jq --arg ns "$ns" '
        .items[] | select(.metadata.namespace == $ns) | .status.summary
    ' 2>/dev/null || echo "{}")

    echo "  Central alerts: $CENTRAL_NS_ALERTS"
    echo "  K8s SR alerts: $K8S_NS_ALERTS"

    if [ "$CENTRAL_NS_ALERTS" -eq "$K8S_NS_ALERTS" ]; then
        echo -e "  ${GREEN}✓ Alert counts match${NC}"
    else
        echo -e "  ${RED}✗ Alert counts don't match${NC}"
    fi

    echo "  K8s SR images: $K8S_NS_IMAGES"
    echo "  Summary: $(echo "$K8S_SUMMARY" | jq -c '.')"
done

echo ""
echo "=== Validation Complete ==="
