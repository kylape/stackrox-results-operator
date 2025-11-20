#!/bin/bash
# Uploads data files to mock Central server

set -e

MOCK_ENDPOINT="${1:-http://mock-central.stackrox.svc:443}"
DATA_DIR="${2:-./data}"

if [ ! -d "$DATA_DIR" ]; then
    echo "Error: Data directory not found: $DATA_DIR"
    echo "Usage: $0 [mock-endpoint] [data-dir]"
    exit 1
fi

echo "======================================"
echo "Uploading data to Mock Central"
echo "======================================"
echo "Endpoint:  $MOCK_ENDPOINT"
echo "Data dir:  $DATA_DIR"
echo ""

# Check for required files
REQUIRED_FILES=("alerts.json" "images.ndjson" "deployments.json" "clusters.json" "nodes.json")
MISSING_FILES=()

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$DATA_DIR/$file" ]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo "Warning: Missing files: ${MISSING_FILES[*]}"
    echo "Continuing with available files..."
    echo ""
fi

# Upload data files
echo "Uploading data files..."
UPLOAD_CMD="curl -X POST $MOCK_ENDPOINT/admin/upload"

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$DATA_DIR/$file" ]; then
        UPLOAD_CMD="$UPLOAD_CMD -F ${file%.*}=@$DATA_DIR/$file"
    fi
done

UPLOAD_RESULT=$($UPLOAD_CMD)
echo "$UPLOAD_RESULT" | jq '.' 2>/dev/null || echo "$UPLOAD_RESULT"
echo ""

# Trigger namespace preprocessing
echo "Triggering namespace preprocessing..."
PREPROCESS_RESULT=$(curl -s -X POST "$MOCK_ENDPOINT/admin/preprocess")
echo "$PREPROCESS_RESULT" | jq '.' 2>/dev/null || echo "$PREPROCESS_RESULT"
echo ""

echo "======================================"
echo "Upload complete!"
echo "======================================"
echo ""
echo "You can now configure the results-operator to use:"
echo "  endpoint: $MOCK_ENDPOINT"
echo ""
echo "Test the mock service:"
echo "  curl $MOCK_ENDPOINT/v1/ping"
echo "  curl $MOCK_ENDPOINT/v1/alerts | jq '.alerts | length'"
