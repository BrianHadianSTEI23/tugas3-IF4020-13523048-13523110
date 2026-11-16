| Scenario | Profile | Expected | Actual | Exit | Marker | Result |
|---|---|---|---|---|---|---|
| C01 | ed25519 | OK (exit 0, marker present) | OK | 0 | present | PASS |
| C01 | ecdsa-p256-sha256 | OK (exit 0, marker present) | OK | 0 | present | PASS |
| C01 | rsa-pss-sha256 | OK (exit 0, marker present) | OK | 0 | present | PASS |
| C02 | ed25519 | ARTIFACT_MISMATCH (exit 1, marker absent) | ARTIFACT_MISMATCH | 1 | absent | PASS |
| C03-empty-trust | ed25519 | KEY_NOT_TRUSTED (exit 1, marker absent) | KEY_NOT_TRUSTED | 1 | absent | PASS |
| C03-other-package | ed25519 | KEY_NOT_TRUSTED (exit 1, marker absent) | KEY_NOT_TRUSTED | 1 | absent | PASS |
| C04 | ed25519 | INPUT_ERROR (exit 2, marker absent) | INPUT_ERROR | 2 | absent | PASS |
| C05 | ecdsa-p256-sha256 | uid match, no TTY, no network, sign and verify work | uid 1001 | - | - | PASS |
