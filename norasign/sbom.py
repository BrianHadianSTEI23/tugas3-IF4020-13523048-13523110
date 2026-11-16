"""
Signed SBOM (Bonus 3).

The SBOM is a CycloneDX 1.5 JSON subset. metadata.component describes the release
artifact and carries its SHA-256, which binds the SBOM to the release. The SBOM file
is signed as an ordinary artifact with the standard minisign-bundle/v1 format.
"""

import collections
import datetime
import hashlib
import json
import os
import re
import sys
import tarfile
import uuid
import zipfile
from typing import Any, Dict, List, Sequence

from norasign import __version__
from norasign.bundle import create_bundle, serialize_bundle
from norasign.constants import (
    RE_ARTIFACT_NAME,
    RE_PACKAGE,
    RE_SHA256,
    RE_VERSION,
    STATUS_FORMAT_ERROR,
    STATUS_INPUT_ERROR,
    STATUS_OK,
)
from norasign.crypto import calculate_keyid, load_private_key_pem, sign_message
from norasign.manifest import build_manifest, strict_json_pairs_hook
from norasign.verifier import exit_code_for, run_verification

STATUS_SBOM_BINDING_MISMATCH = "SBOM_BINDING_MISMATCH"
MAX_SBOM_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
PROP_ARTIFACT_NAME = "norasign:artifact:name"
PROP_ARTIFACT_SIZE = "norasign:artifact:size"
_RE_COMPONENT = re.compile(r"^([^@\s]+)@([^@\s]+)$")


class SbomFormatError(Exception):
    pass


def _hash_file(path: str):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def _file_component(name: str, data: bytes) -> Dict[str, Any]:
    return collections.OrderedDict(
        [
            ("type", "file"),
            ("bom-ref", f"file:{name}"),
            ("name", name),
            ("hashes", [collections.OrderedDict([("alg", "SHA-256"), ("content", hashlib.sha256(data).hexdigest())])]),
            ("properties", [collections.OrderedDict([("name", "norasign:file:size"), ("value", str(len(data)))])]),
        ]
    )


def _archive_components(path: str) -> List[Dict[str, Any]]:
    """List regular files inside a zip/tar archive. Members are read in memory, never written to disk."""
    components = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                    if not info.is_dir():
                        components.append(_file_component(info.filename, zf.read(info)))
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                for member in tf.getmembers()[:MAX_ARCHIVE_MEMBERS]:
                    if member.isfile():
                        fh = tf.extractfile(member)
                        components.append(_file_component(member.name, fh.read() if fh else b""))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return []
    return components


def build_sbom(
    artifact_path: str,
    package: str,
    version: str,
    components: Sequence[str] = (),
    scan_archive: bool = True,
) -> Dict[str, Any]:
    if not RE_PACKAGE.match(package or ""):
        raise ValueError(f"invalid package name '{package}'")
    if not RE_VERSION.match(version or ""):
        raise ValueError(f"invalid version '{version}'")
    name = os.path.basename(artifact_path)
    if not RE_ARTIFACT_NAME.match(name):
        raise ValueError(f"invalid artifact filename '{name}'")
    size, sha256 = _hash_file(artifact_path)

    comp_list: List[Dict[str, Any]] = []
    for spec in components:
        m = _RE_COMPONENT.match(spec)
        if not m:
            raise ValueError(f"component '{spec}' must use the form name@version")
        comp_list.append(
            collections.OrderedDict(
                [
                    ("type", "library"),
                    ("bom-ref", f"pkg:{m.group(1)}@{m.group(2)}"),
                    ("name", m.group(1)),
                    ("version", m.group(2)),
                ]
            )
        )
    if scan_archive:
        comp_list.extend(_archive_components(artifact_path))

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return collections.OrderedDict(
        [
            ("bomFormat", "CycloneDX"),
            ("specVersion", "1.5"),
            ("serialNumber", f"urn:uuid:{uuid.uuid4()}"),
            ("version", 1),
            (
                "metadata",
                collections.OrderedDict(
                    [
                        ("timestamp", timestamp),
                        (
                            "tools",
                            {"components": [{"type": "application", "name": "norasign", "version": __version__}]},
                        ),
                        (
                            "component",
                            collections.OrderedDict(
                                [
                                    ("type", "application"),
                                    ("bom-ref", f"{package}@{version}"),
                                    ("name", package),
                                    ("version", version),
                                    ("hashes", [collections.OrderedDict([("alg", "SHA-256"), ("content", sha256)])]),
                                    (
                                        "properties",
                                        [
                                            collections.OrderedDict([("name", PROP_ARTIFACT_NAME), ("value", name)]),
                                            collections.OrderedDict([("name", PROP_ARTIFACT_SIZE), ("value", str(size))]),
                                        ],
                                    ),
                                ]
                            ),
                        ),
                    ]
                ),
            ),
            ("components", comp_list),
        ]
    )


def generate_sbom(
    artifact_path: str,
    out_path: str,
    package: str = "",
    version: str = "",
    components: Sequence[str] = (),
    scan_archive: bool = True,
    quiet: bool = False,
) -> Dict[str, Any]:
    sbom = build_sbom(artifact_path, package, version, components, scan_archive)
    data = (json.dumps(sbom, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_SBOM_BYTES:
        raise ValueError(f"SBOM exceeds {MAX_SBOM_BYTES} bytes")
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)
    if not quiet:
        meta = sbom["metadata"]["component"]
        print(f"SBOM written to {out_path}")
        print(f"  Package:    {meta['name']} v{meta['version']}")
        print(f"  Artifact:   {os.path.basename(artifact_path)}")
        print(f"  SHA-256:    {meta['hashes'][0]['content']}")
        print(f"  Components: {len(sbom['components'])}")
    return sbom


def parse_sbom(raw: bytes) -> Dict[str, Any]:
    """Strict parse of the fields NoraSign relies on. Returns the binding information."""
    if len(raw) > MAX_SBOM_BYTES:
        raise SbomFormatError(f"SBOM exceeds {MAX_SBOM_BYTES} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SbomFormatError("SBOM contains UTF-8 BOM")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_json_pairs_hook)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise SbomFormatError(f"SBOM JSON invalid: {e}")
    if not isinstance(doc, dict):
        raise SbomFormatError("SBOM root must be an object")
    if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != "1.5":
        raise SbomFormatError("SBOM must be CycloneDX specVersion 1.5")
    if not isinstance(doc.get("components"), list):
        raise SbomFormatError("SBOM 'components' must be an array")
    meta = doc.get("metadata")
    comp = meta.get("component") if isinstance(meta, dict) else None
    if not isinstance(comp, dict):
        raise SbomFormatError("SBOM metadata.component is required")

    name, version = comp.get("name"), comp.get("version")
    if not isinstance(name, str) or not RE_PACKAGE.match(name):
        raise SbomFormatError("metadata.component.name must be a valid package name")
    if not isinstance(version, str) or not RE_VERSION.match(version):
        raise SbomFormatError("metadata.component.version must be a valid version")

    hashes = comp.get("hashes")
    if not isinstance(hashes, list):
        raise SbomFormatError("metadata.component.hashes must be an array")
    sha_values = [h.get("content") for h in hashes if isinstance(h, dict) and h.get("alg") == "SHA-256"]
    if len(sha_values) != 1 or not isinstance(sha_values[0], str) or not RE_SHA256.match(sha_values[0]):
        raise SbomFormatError("metadata.component must carry exactly one lowercase SHA-256 hash")

    props = comp.get("properties")
    if not isinstance(props, list):
        raise SbomFormatError("metadata.component.properties must be an array")
    prop_map: Dict[str, List[Any]] = {}
    for p in props:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("value"), str):
            raise SbomFormatError("each property must have string name and value")
        prop_map.setdefault(p["name"], []).append(p["value"])
    if len(prop_map.get(PROP_ARTIFACT_NAME, [])) != 1 or len(prop_map.get(PROP_ARTIFACT_SIZE, [])) != 1:
        raise SbomFormatError(f"properties {PROP_ARTIFACT_NAME} and {PROP_ARTIFACT_SIZE} must appear exactly once")
    size_str = prop_map[PROP_ARTIFACT_SIZE][0]
    if not re.fullmatch(r"0|[1-9][0-9]*", size_str):
        raise SbomFormatError("artifact size property must be a decimal integer")

    return {
        "package": name,
        "version": version,
        "artifact_name": prop_map[PROP_ARTIFACT_NAME][0],
        "artifact_size": int(size_str),
        "artifact_sha256": sha_values[0],
        "component_count": len(doc["components"]),
    }


def sign_sbom(sbom_path: str, key_path: str, out_path: str, quiet: bool = False) -> Dict[str, Any]:
    """Sign the SBOM file as a separate artifact. Package and version come from the SBOM."""
    with open(sbom_path, "rb") as f:
        info = parse_sbom(f.read(MAX_SBOM_BYTES + 1))
    with open(key_path, "rb") as f:
        private_key, algorithm = load_private_key_pem(f.read())
    keyid = calculate_keyid(private_key.public_key())
    _, manifest_bytes = build_manifest(sbom_path, info["package"], info["version"], algorithm, keyid)
    signature = sign_message(private_key, algorithm, manifest_bytes)
    bundle_bytes = serialize_bundle(create_bundle(manifest_bytes, signature))
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(bundle_bytes)
    if not quiet:
        print(f"Signed SBOM '{sbom_path}'")
        print(f"  Package:   {info['package']} v{info['version']}")
        print(f"  Algorithm: {algorithm}")
        print(f"  Key ID:    {keyid}")
        print(f"  Bundle:    {out_path}")
    return {"package": info["package"], "version": info["version"], "algorithm": algorithm, "keyid": keyid}


def _sbom_result(status: str, stage: str, message: str, release=None, sbom=None, binding=None) -> Dict[str, Any]:
    return collections.OrderedDict(
        [
            ("valid", status == STATUS_OK),
            ("status", status),
            ("stage", stage),
            ("message", message),
            ("release", release),
            ("sbom", sbom),
            ("binding", binding),
        ]
    )


def run_sbom_verification(
    artifact_path: str,
    artifact_bundle_path: str,
    sbom_path: str,
    sbom_bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
) -> Dict[str, Any]:
    release = run_verification(artifact_path, artifact_bundle_path, trust_store_path, package, version)
    if not release["valid"]:
        return _sbom_result(release["status"], "release", f"Release bundle rejected: {release['message']}", release)

    sbom_res = run_verification(sbom_path, sbom_bundle_path, trust_store_path, package, version)
    if not sbom_res["valid"]:
        return _sbom_result(sbom_res["status"], "sbom", f"SBOM bundle rejected: {sbom_res['message']}", release, sbom_res)

    try:
        with open(sbom_path, "rb") as f:
            info = parse_sbom(f.read(MAX_SBOM_BYTES + 1))
        artifact_size, artifact_sha256 = _hash_file(artifact_path)
    except OSError as e:
        return _sbom_result(STATUS_INPUT_ERROR, "binding", f"I/O error: {e}", release, sbom_res)
    except SbomFormatError as e:
        return _sbom_result(STATUS_FORMAT_ERROR, "binding", f"SBOM content invalid: {e}", release, sbom_res)

    binding = collections.OrderedDict(
        [
            ("sbom_artifact_sha256", info["artifact_sha256"]),
            ("release_artifact_sha256", artifact_sha256),
            ("sbom_artifact_name", info["artifact_name"]),
            ("release_artifact_name", os.path.basename(artifact_path)),
            ("components", info["component_count"]),
        ]
    )
    checks = [
        (info["package"] == package and info["version"] == version, "SBOM package/version differ from expected"),
        (info["artifact_sha256"] == artifact_sha256, "SBOM SHA-256 differs from release artifact SHA-256"),
        (info["artifact_name"] == os.path.basename(artifact_path), "SBOM artifact name differs from release artifact"),
        (info["artifact_size"] == artifact_size, "SBOM artifact size differs from release artifact"),
    ]
    for ok, msg in checks:
        if not ok:
            return _sbom_result(STATUS_SBOM_BINDING_MISMATCH, "binding", msg, release, sbom_res, binding)
    return _sbom_result(STATUS_OK, "binding", "Release, SBOM, and SHA-256 binding are valid.", release, sbom_res, binding)


def verify_sbom(
    artifact_path: str,
    artifact_bundle_path: str,
    sbom_path: str,
    sbom_bundle_path: str,
    trust_store_path: str,
    package: str,
    version: str,
    json_output: bool = False,
    emit: bool = True,
) -> Dict[str, Any]:
    result = run_sbom_verification(
        artifact_path, artifact_bundle_path, sbom_path, sbom_bundle_path, trust_store_path, package, version
    )
    result["exit_code"] = exit_code_for(result["status"])
    if emit:
        printable = {k: v for k, v in result.items() if k != "exit_code"}
        if json_output:
            sys.stdout.write(json.dumps(printable) + "\n")
            if not result["valid"]:
                sys.stderr.write(f"norasign sbom verify: {result['status']} ({result['stage']}): {result['message']}\n")
        else:
            stream = sys.stdout if result["valid"] else sys.stderr
            stream.write(f"{result['status']} ({result['stage']}): {result['message']}\n")
    return result
