"""
Constants and specifications for NoraSign.
IF4020 Kriptografi - Chapter 3: Penandatanganan dan Verifikasi Software Release.
"""

import re

# Exit codes (Tabel 2.10)
EXIT_SUCCESS = 0          # Command successful (for verify: valid=True, status=OK)
EXIT_VERIFY_REJECTED = 1  # Verification rejected (FORMAT_ERROR, UNSUPPORTED_ALGORITHM, etc.)
EXIT_USAGE_OR_IO_ERROR = 2  # Input error, usage error, missing parameters, I/O failures

# Verification status strings (Tabel 2.8)
STATUS_OK = "OK"
STATUS_INPUT_ERROR = "INPUT_ERROR"
STATUS_FORMAT_ERROR = "FORMAT_ERROR"
STATUS_UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
STATUS_KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
STATUS_INVALID_SIGNATURE = "INVALID_SIGNATURE"
STATUS_METADATA_MISMATCH = "METADATA_MISMATCH"
STATUS_ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"

ALL_STATUSES = [
    STATUS_OK,
    STATUS_INPUT_ERROR,
    STATUS_FORMAT_ERROR,
    STATUS_UNSUPPORTED_ALGORITHM,
    STATUS_KEY_NOT_TRUSTED,
    STATUS_INVALID_SIGNATURE,
    STATUS_METADATA_MISMATCH,
    STATUS_ARTIFACT_MISMATCH,
]

# Supported algorithm profiles (Tabel 2.1)
ALG_RSA_PSS = "rsa-pss-sha256"
ALG_ECDSA_P256 = "ecdsa-p256-sha256"
ALG_ED25519 = "ed25519"

SUPPORTED_ALGORITHMS = [
    ALG_RSA_PSS,
    ALG_ECDSA_P256,
    ALG_ED25519,
]

# Signature byte lengths
SIG_LENGTH_RSA_PSS = 384
SIG_LENGTH_ECDSA_P256 = 64
SIG_LENGTH_ED25519 = 64

SIGNATURE_LENGTHS = {
    ALG_RSA_PSS: SIG_LENGTH_RSA_PSS,
    ALG_ECDSA_P256: SIG_LENGTH_ECDSA_P256,
    ALG_ED25519: SIG_LENGTH_ED25519,
}

# Schemas
SCHEMA_MANIFEST = "minisign-manifest/v1"
SCHEMA_BUNDLE = "minisign-bundle/v1"
SCHEMA_TRUST = "minisign-trust/v1"

# Maximum file sizes
MAX_MANIFEST_BYTES = 16 * 1024       # 16 KiB = 16,384 bytes
MAX_BUNDLE_BYTES = 64 * 1024         # 64 KiB = 65,536 bytes
MAX_ARTIFACT_SIZE = 9007199254740991 # 2^53 - 1 (IEEE-754 binary64 safe integer)

# Regular expressions (Tabel 2.3)
RE_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
RE_KEYID = re.compile(r"^[0-9a-f]{64}$")
RE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Manifest canonical field sequences
MANIFEST_FIELD_ORDER = ["schema", "package", "version", "algorithm", "keyid", "artifact"]
ARTIFACT_FIELD_ORDER = ["name", "size", "sha256"]
BUNDLE_FIELD_ORDER = ["schema", "manifest_b64", "signature_b64"]
