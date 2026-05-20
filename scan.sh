#!/bin/sh

echo "Installing Trivy..."
apk add --no-cache curl
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

echo "Waiting for API server to be ready..."
sleep 30

while true; do
  echo "=== DTrack scanner starting at $(date) ==="

  IMAGES=$(docker ps --format '{{.Image}}'; docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' || true)
  IMAGES=$(echo "$IMAGES" | sort -u)

  for IMAGE in $IMAGES; do
    echo ""
    echo "--- Scanning: $IMAGE ---"

    PROJECT_NAME=$(echo "$IMAGE" | cut -d: -f1 | sed 's|.*/||')
    PROJECT_VERSION=$(echo "$IMAGE" | cut -s -d: -f2)
    PROJECT_VERSION="${PROJECT_VERSION:-latest}"

    PROJECT_RESPONSE=$(curl -sf \
      -H "X-Api-Key: $DTRACK_API_KEY" \
      -H "Content-Type: application/json" \
      -X PUT \
      -d "{\"name\":\"$PROJECT_NAME\",\"version\":\"$PROJECT_VERSION\",\"classifier\":\"CONTAINER\"}" \
      "$DTRACK_URL/api/v1/project")

    PROJECT_UUID=$(echo "$PROJECT_RESPONSE" | grep -o '"uuid":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$PROJECT_UUID" ]; then
      echo "  Could not create/find project for $IMAGE — skipping"
      continue
    fi

    echo "  Project UUID: $PROJECT_UUID"

    trivy image \
      --format cyclonedx \
      --output /tmp/sbom.json \
      --quiet \
      "$IMAGE"

    if [ ! -s /tmp/sbom.json ]; then
      echo "  SBOM empty or failed — skipping"
      continue
    fi

    curl -sf \
      -H "X-Api-Key: $DTRACK_API_KEY" \
      -H "Content-Type: application/vnd.cyclonedx+json" \
      -X PUT \
      --data-binary @/tmp/sbom.json \
      "$DTRACK_URL/api/v1/bom?project=$PROJECT_UUID"

    echo "  Uploaded successfully"
    rm -f /tmp/sbom.json
  done

  echo ""
  echo "=== Scan complete at $(date). Next run in ${SCAN_INTERVAL}s ==="
  sleep "$SCAN_INTERVAL"
done
