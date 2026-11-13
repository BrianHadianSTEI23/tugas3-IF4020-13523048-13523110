#!/usr/bin/env bash
# run_ci_scenarios.sh
# Local simulation and automated test of CI/CD Integration Scenarios C01 - C05
# IF4020 Kriptografi Chapter 3 - Section 2.9 & Table 2.15

set -euo pipefail

IMAGE_NAME="${1:-norasign:local}"
echo "=== Running CI/CD Container Scenarios using image: $IMAGE_NAME ==="

TMP_DIR=$(mktemp -d /tmp/norasign-ci-test.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/dist" "$TMP_DIR/out" "$TMP_DIR/ci" "$TMP_DIR/keys"

# Create mock artifact
echo "Sample application release payload for CI testing" > "$TMP_DIR/dist/sample-app.zip"

echo "[Test] Scenario C05: Verify CLI runs with runner UID/GID, no TTY, and --network none..."
docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    "$IMAGE_NAME" --version > /dev/null
echo "  [PASS] C05: Container executed without network, non-root user, no TTY."

echo "[Test] Scenario C01 (Signing stage): Generate key and sign release artifact..."
# Generate keypair inside container
docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    -v "$TMP_DIR/keys:/keys" \
    "$IMAGE_NAME" keygen --algorithm ed25519 --out /keys/ci_publisher > /dev/null

# Sign artifact inside container
docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    -v "$TMP_DIR/dist:/input:ro" \
    -v "$TMP_DIR/out:/output" \
    -v "$TMP_DIR/keys/ci_publisher.key.pem:/run/signing.key.pem:ro" \
    "$IMAGE_NAME" sign \
    --file /input/sample-app.zip \
    --package sample-app \
    --version 1.0.0 \
    --key /run/signing.key.pem \
    --out /output/release.bundle.json > /dev/null

if [ -f "$TMP_DIR/out/release.bundle.json" ]; then
    echo "  [PASS] C01 (Sign): Release bundle successfully generated."
else
    echo "  [FAIL] C01 (Sign): Release bundle not found!"
    exit 1
fi

echo "=== Core Container & Signing CI Scenarios Successfully Validated ==="
