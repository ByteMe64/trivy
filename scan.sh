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

    # Try to create project
    HTTP_CODE=$(curl -s -o /tmp/project_response.json -w "%{http_code}" \
      -H "X-Api-Key: $DTRACK_API_KEY" \
      -H "Content-Type: application/json" \
      -X PUT \
      -d "{\"name\":\"$PROJECT_NAME\",\"version\":\"$PROJECT_VERSION\",\"classifier\":\"CONTAINER\"}" \
      "$DTRACK_URL/api/v1/project")

    echo "  Project create HTTP: $HTTP_CODE"

    if [ "$HTTP_CODE" = "201" ]; then
      # Created successfully
      PROJECT_UUID=$(grep -o '"uuid":"[^"]*"' /tmp/project_response.json | head -1 | cut -d'"' -f4)
    elif [ "$HTTP_CODE" = "409" ]; then
      # Already exists — look it up by name and version
      echo "  Project exists, looking up UUID..."
      curl -s -o /tmp/project_response.json \
        -H "X-Api-Key: $DTRACK_API_KEY" \
        "$DTRACK_URL/api/v1/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION"
      PROJECT_UUID=$(grep -o '"uuid":"[^"]*"' /tmp/project_response.json | head -1 | cut -d'"' -f4)
    else
      echo "  Unexpected response: $HTTP_CODE"
      cat /tmp/project_response.json
      continue
    fi

    if [ -z "$PROJECT_UUID" ]; then
      echo "  Could not get project UUID — skipping"
      cat /tmp/project_response.json
      continue
    fi

    echo "  Project UUID: $PROJECT_UUID"

    trivy image \
      --format cyclonedx \
      --output /tmp/sbom.json \
      --quiet \
      "$IMAGE" || true

    if [ ! -s /tmp/sbom.json ]; then
      echo "  SBOM empty or failed — skipping"
      continue
    fi

    curl -s -o /dev/null -w "  Upload HTTP: %{http_code}\n" \
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
