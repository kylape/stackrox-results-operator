#!/usr/bin/env bash

set -euo pipefail

# Script to fetch a StackRox API token using admin credentials
# Usage: ./get-api-token.sh <password-file>

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <password-file>"
    echo "Example: $0 /path/to/admin-password.txt"
    exit 1
fi

PASSWORD_FILE="$1"

if [[ ! -f "$PASSWORD_FILE" ]]; then
    echo "Error: Password file not found: $PASSWORD_FILE"
    exit 1
fi

ADMIN_PASSWORD=$(cat "$PASSWORD_FILE")

# Set up port-forward to Central
echo "[API-TOKEN] Setting up port-forward to Central..." >&2
kubectl port-forward -n stackrox svc/central 8443:443 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!

# Ensure port-forward is killed on exit
trap "kill ${PORT_FORWARD_PID} 2>/dev/null || true" EXIT

# Wait for port-forward to be ready
sleep 2

# Create API token via Central API
echo "[API-TOKEN] Creating API token for results-operator..." >&2

# Generate token name with timestamp
TOKEN_NAME="results-operator-$(date +%Y%m%d-%H%M%S)"

# Create the API token request payload
TOKEN_REQUEST=$(cat <<EOF
{
  "name": "$TOKEN_NAME",
  "role": "Admin",
  "expiration": null
}
EOF
)

# Make the API call to create token
RESPONSE=$(curl -sk \
    -u "admin:${ADMIN_PASSWORD}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$TOKEN_REQUEST" \
    "https://localhost:8443/v1/apitokens/generate")

# Kill port-forward
kill ${PORT_FORWARD_PID} 2>/dev/null || true
wait ${PORT_FORWARD_PID} 2>/dev/null || true

# Extract token from response
API_TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty')

if [[ -z "$API_TOKEN" ]]; then
    echo "[API-TOKEN] Error: Failed to extract token from response:" >&2
    echo "$RESPONSE" | jq . >&2
    exit 1
fi

echo "[API-TOKEN] Successfully created API token: $TOKEN_NAME" >&2
echo "[API-TOKEN] Token ID: $(echo "$RESPONSE" | jq -r '.id')" >&2

# Create Kubernetes secret with the API token
SECRET_NAME="${SECRET_NAME:-central-auth}"
SECRET_NAMESPACE="${SECRET_NAMESPACE:-stackrox}"

echo "[API-TOKEN] Creating Kubernetes secret: $SECRET_NAME in namespace $SECRET_NAMESPACE..." >&2

# Create namespace if it doesn't exist
kubectl create namespace "$SECRET_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >&2

# Create or update the secret
kubectl create secret generic "$SECRET_NAME" \
    --from-literal=token="$API_TOKEN" \
    --namespace="$SECRET_NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f - >&2

echo "[API-TOKEN] Secret created successfully!" >&2
echo "[API-TOKEN] Use this in ResultsExporter:" >&2
echo "[API-TOKEN]   spec.central.authSecretName: $SECRET_NAME" >&2
echo "[API-TOKEN]   spec.central.authSecretNamespace: $SECRET_NAMESPACE" >&2
