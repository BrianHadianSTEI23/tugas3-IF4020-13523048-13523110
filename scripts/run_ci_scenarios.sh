#!/usr/bin/env bash
# CI/CD integration scenarios C01-C05 (Table 2.15).
# Usage: bash scripts/run_ci_scenarios.sh <image-reference> [evidence-dir]
# Every scenario runs in a clean directory. Negative cases read the real exit code of
# the container before reporting a rejection, and the deploy marker is created only
# when verify exits 0.

set -u

IMAGE="${1:?usage: $0 <image-reference> [evidence-dir]}"
EVIDENCE="$(realpath -m "${2:-ci-evidence}")"
ROOT="$(mktemp -d)"
FAILS=0
ALGOS="ed25519 ecdsa-p256-sha256 rsa-pss-sha256"
PKG="sample-app"
VER="1.0.0"

trap 'rm -rf "$ROOT"' EXIT
rm -rf "$EVIDENCE"
mkdir -p "$EVIDENCE"
printf '| Scenario | Profile | Expected | Actual | Exit | Marker | Result |\n|---|---|---|---|---|---|---|\n' > "$EVIDENCE/summary.md"

nora() { docker run --rm --network none --user "$(id -u):$(id -g)" "$@"; }

status_of() { sed -n 's/.*"status": "\([A-Z_]*\)".*/\1/p' "$1" 2>/dev/null | head -n 1; }

prepare() {
    local d="$1" algo="$2"
    rm -rf "$d"
    mkdir -p "$d/dist" "$d/out" "$d/keys" "$d/ci"
    printf 'NoraSign CI artifact for %s\n' "$algo" > "$d/dist/$PKG.zip"
    nora -v "$d/keys:/keys" "$IMAGE" keygen --algorithm "$algo" --out /keys/signer > "$d/out/keygen.log" || return 1
    nora -v "$d/keys:/keys:ro" -v "$d/ci:/ci" "$IMAGE" trust add \
        --key /keys/signer.pub.pem --package "$PKG" --store /ci/trust.json > "$d/out/trust-add.log" || return 1
}

sign_release() {
    local d="$1"
    nora -v "$d/dist:/input:ro" -v "$d/out:/output" \
        -v "$d/keys/signer.key.pem:/run/signing.key.pem:ro" \
        "$IMAGE" sign --file "/input/$PKG.zip" --package "$PKG" --version "$VER" \
        --key /run/signing.key.pem --out /output/release.bundle.json > "$d/out/sign.log"
    local rc=$?
    rm -f "$d/keys/signer.key.pem"
    return $rc
}

verify_release() {
    local d="$1" file="$2" trust="$3"
    nora -v "$d/dist:/input:ro" -v "$d/out:/output:ro" -v "$d/ci:/ci:ro" \
        "$IMAGE" verify --file "$file" --bundle /output/release.bundle.json \
        --trust-store "$trust" --package "$PKG" --version "$VER" --json \
        > "$d/out/verification.json" 2> "$d/out/verify.stderr"
}

gate_deploy() {
    local d="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        printf 'deployed %s %s\n' "$PKG" "$VER" > "$d/out/deploy.marker"
    fi
}

record() {
    local id="$1" algo="$2" d="$3" exp_status="$4" exp_exit="$5" rc="$6" exp_marker="$7"
    local status marker result="PASS"
    status="$(status_of "$d/out/verification.json")"
    [ -f "$d/out/deploy.marker" ] && marker="present" || marker="absent"
    [ "$status" = "$exp_status" ] || result="FAIL"
    [ "$rc" -eq "$exp_exit" ] || result="FAIL"
    [ "$marker" = "$exp_marker" ] || result="FAIL"
    [ "$result" = "PASS" ] || FAILS=$((FAILS + 1))
    printf '[%s] %s %-18s expected=%-18s actual=%-18s exit=%s marker=%s\n' \
        "$result" "$id" "$algo" "$exp_status" "${status:-none}" "$rc" "$marker"
    printf '| %s | %s | %s (exit %s, marker %s) | %s | %s | %s | %s |\n' \
        "$id" "$algo" "$exp_status" "$exp_exit" "$exp_marker" "${status:-none}" "$rc" "$marker" "$result" >> "$EVIDENCE/summary.md"
    rm -rf "$EVIDENCE/$id-$algo"
    mkdir -p "$EVIDENCE/$id-$algo"
    cp -r "$d/out/." "$EVIDENCE/$id-$algo/"
    cp "$d/ci/"*.json "$EVIDENCE/$id-$algo/" 2>/dev/null
}

echo "Image under test: $IMAGE"

for algo in $ALGOS; do
    D="$ROOT/C01-$algo"
    if ! prepare "$D" "$algo" || ! sign_release "$D"; then
        echo "[FAIL] C01 $algo: key preparation or sign failed"
        FAILS=$((FAILS + 1))
        continue
    fi
    verify_release "$D" "/input/$PKG.zip" /ci/trust.json
    rc=$?
    gate_deploy "$D" "$rc"
    record C01 "$algo" "$D" OK 0 "$rc" present
done

D="$ROOT/C02"
prepare "$D" ed25519 && sign_release "$D"
printf 'X' | dd of="$D/dist/$PKG.zip" bs=1 seek=5 conv=notrunc status=none
verify_release "$D" "/input/$PKG.zip" /ci/trust.json
rc=$?
gate_deploy "$D" "$rc"
record C02 ed25519 "$D" ARTIFACT_MISMATCH 1 "$rc" absent

D="$ROOT/C03a"
prepare "$D" ed25519 && sign_release "$D"
printf '{\n  "schema": "minisign-trust/v1",\n  "keys": []\n}\n' > "$D/ci/empty-trust.json"
verify_release "$D" "/input/$PKG.zip" /ci/empty-trust.json
rc=$?
gate_deploy "$D" "$rc"
record C03-empty-trust ed25519 "$D" KEY_NOT_TRUSTED 1 "$rc" absent

D="$ROOT/C03b"
prepare "$D" ed25519 && sign_release "$D"
nora -v "$D/ci:/ci" -v "$D/keys:/keys:ro" "$IMAGE" trust add \
    --key /keys/signer.pub.pem --package other-app --store /ci/other-package-trust.json > /dev/null
verify_release "$D" "/input/$PKG.zip" /ci/other-package-trust.json
rc=$?
gate_deploy "$D" "$rc"
record C03-other-package ed25519 "$D" KEY_NOT_TRUSTED 1 "$rc" absent

D="$ROOT/C04"
prepare "$D" ed25519 && sign_release "$D"
verify_release "$D" /input/missing.zip /ci/trust.json
rc=$?
gate_deploy "$D" "$rc"
record C04 ed25519 "$D" INPUT_ERROR 2 "$rc" absent

C05=PASS
uid_in="$(nora --entrypoint id "$IMAGE" -u)"
[ "$uid_in" = "$(id -u)" ] || C05=FAIL
nora --entrypoint sh "$IMAGE" -c '[ ! -t 0 ] && [ ! -t 1 ]' < /dev/null || C05=FAIL
nora --entrypoint python "$IMAGE" -c \
    "import socket
try:
    socket.create_connection(('1.1.1.1', 53), 3)
except OSError:
    raise SystemExit(0)
raise SystemExit(1)" || C05=FAIL
nora "$IMAGE" --version > "$EVIDENCE/C05-version.txt" || C05=FAIL
nora "$IMAGE" --help > /dev/null || C05=FAIL
D="$ROOT/C05"
prepare "$D" ecdsa-p256-sha256 && sign_release "$D"
verify_release "$D" "/input/$PKG.zip" /ci/trust.json || C05=FAIL
printf '[%s] C05 uid=%s (runner %s), no TTY, network blocked, full flow under --user\n' "$C05" "$uid_in" "$(id -u)"
printf '| C05 | ecdsa-p256-sha256 | uid match, no TTY, no network, sign and verify work | uid %s | - | - | %s |\n' "$uid_in" "$C05" >> "$EVIDENCE/summary.md"
[ "$C05" = PASS ] || FAILS=$((FAILS + 1))

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS scenario(s) failed"
    exit 1
fi
echo "All CI scenarios passed. Evidence: $EVIDENCE"
