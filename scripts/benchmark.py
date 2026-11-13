#!/usr/bin/env python3
"""
Performance benchmark script for NoraSign according to Table 2.12.
IF4020 Kriptografi Chapter 3 - Section 2.8.
"""

import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization

from norasign.constants import (
    ALG_ECDSA_P256,
    ALG_ED25519,
    ALG_RSA_PSS,
    SUPPORTED_ALGORITHMS,
)
from norasign.crypto import (
    generate_keypair,
    save_keypair_files,
    sign_message,
    verify_message_signature,
)
from norasign.manifest import build_manifest


def calculate_p95(data: List[float]) -> float:
    """Calculate 95th percentile using nearest-rank method: ceil(0.95 * n)."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    idx = max(0, int(math.ceil(0.95 * n)) - 1)
    return sorted_data[idx]


def measure_key_generation(algo: str, count: int = 10) -> Dict[str, float]:
    """Measure key generation duration for at least 5 keypairs."""
    durations_ms = []
    for _ in range(count):
        t0 = time.perf_counter_ns()
        priv, pub = generate_keypair(algo)
        t1 = time.perf_counter_ns()
        durations_ms.append((t1 - t0) / 1_000_000.0)
    return {
        "median_ms": statistics.median(durations_ms),
        "p95_ms": calculate_p95(durations_ms),
    }


def measure_artifact_hash(file_path: str, warmup: int = 5, runs: int = 30) -> Dict[str, float]:
    """Measure SHA-256 calculation over artifact bytes."""
    with open(file_path, "rb") as f:
        content = f.read()

    for _ in range(warmup):
        hashlib.sha256(content).hexdigest()

    durations_ms = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        h = hashlib.sha256(content).hexdigest()
        t1 = time.perf_counter_ns()
        durations_ms.append((t1 - t0) / 1_000_000.0)

    return {
        "median_ms": statistics.median(durations_ms),
        "p95_ms": calculate_p95(durations_ms),
    }


def measure_crypto_sign_verify(
    algo: str,
    manifest_bytes: bytes,
    warmup: int = 5,
    runs: int = 30,
) -> Tuple[Dict[str, float], Dict[str, float]]:
    """Measure pure crypto sign and verify operations over manifest bytes."""
    priv, pub = generate_keypair(algo)

    # Warmup
    for _ in range(warmup):
        s = sign_message(priv, algo, manifest_bytes)
        verify_message_signature(pub, algo, manifest_bytes, s)

    sign_ms = []
    verify_ms = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        sig = sign_message(priv, algo, manifest_bytes)
        t1 = time.perf_counter_ns()
        sign_ms.append((t1 - t0) / 1_000_000.0)

        t2 = time.perf_counter_ns()
        valid = verify_message_signature(pub, algo, manifest_bytes, sig)
        t3 = time.perf_counter_ns()
        assert valid is True
        verify_ms.append((t3 - t2) / 1_000_000.0)

    res_sign = {
        "median_ms": statistics.median(sign_ms),
        "p95_ms": calculate_p95(sign_ms),
    }
    res_verify = {
        "median_ms": statistics.median(verify_ms),
        "p95_ms": calculate_p95(verify_ms),
    }
    return res_sign, res_verify


def measure_end_to_end_cli(
    algo: str,
    artifact_path: str,
    warmup: int = 5,
    runs: int = 30,
) -> Dict[str, float]:
    """Measure End-to-End CLI signing execution duration."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_prefix = os.path.join(tmpdir, "signer")
        save_keypair_files(algo, key_prefix)
        key_path = key_prefix + ".key.pem"
        bundle_out = os.path.join(tmpdir, "release.bundle.json")

        cmd = [
            "python3", "-m", "norasign.cli", "sign",
            "--file", artifact_path,
            "--package", "benchmark-pkg",
            "--version", "1.0.0",
            "--key", key_path,
            "--out", bundle_out,
        ]

        # Warmup
        for _ in range(warmup):
            subprocess.run(cmd, capture_output=True, check=True)

        durations_ms = []
        for _ in range(runs):
            t0 = time.perf_counter_ns()
            subprocess.run(cmd, capture_output=True, check=True)
            t1 = time.perf_counter_ns()
            durations_ms.append((t1 - t0) / 1_000_000.0)

        return {
            "median_ms": statistics.median(durations_ms),
            "p95_ms": calculate_p95(durations_ms),
        }


def get_sizes(algo: str, manifest_bytes: bytes) -> Dict[str, int]:
    """Measure key, signature, and bundle sizes in bytes."""
    priv, pub = generate_keypair(algo)
    priv_der = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_sig = sign_message(priv, algo, manifest_bytes)

    from norasign.bundle import create_bundle, serialize_bundle
    bundle = create_bundle(manifest_bytes, raw_sig)
    bundle_bytes = serialize_bundle(bundle)

    return {
        "priv_key_der_bytes": len(priv_der),
        "pub_key_der_bytes": len(pub_der),
        "signature_raw_bytes": len(raw_sig),
        "bundle_bytes": len(bundle_bytes),
    }


def main():
    parser = argparse.ArgumentParser(description="Run NoraSign Performance Benchmarks")
    parser.add_argument("--runs", type=int, default=30, help="Number of measured runs (default: 30)")
    parser.add_argument("--warmup", type=int, default=5, help="Number of warmup runs (default: 5)")
    parser.add_argument("--out", default="benchmark_results.md", help="Output markdown report path")
    parser.add_argument("--csv", default="benchmark_raw.csv", help="Output CSV path")
    args = parser.parse_args()

    print(f"Starting NoraSign Benchmark Suite: Warmup={args.warmup}, Runs={args.runs}")

    # Create 3 diverse artifacts
    sizes = [
        ("1 KB", 1024),
        ("10 MB", 10 * 1024 * 1024),
        ("50 MB", 50 * 1024 * 1024),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_paths = {}
        for label, size_bytes in sizes:
            p = os.path.join(tmpdir, f"artifact_{size_bytes}.dat")
            with open(p, "wb") as f:
                f.write(os.urandom(size_bytes))
            artifact_paths[label] = p

        results = {}

        # 1. Key Generation
        print("\n[1/5] Benchmarking Key Generation...")
        keygen_res = {}
        for algo in SUPPORTED_ALGORITHMS:
            kg = measure_key_generation(algo, count=10)
            keygen_res[algo] = kg
            print(f"  {algo:18s} -> Median: {kg['median_ms']:.3f} ms, P95: {kg['p95_ms']:.3f} ms")
        results["keygen"] = keygen_res

        # 2. Artifact Hashing
        print("\n[2/5] Benchmarking Artifact Hashing (SHA-256)...")
        hash_res = {}
        for label, path in artifact_paths.items():
            h_stat = measure_artifact_hash(path, warmup=args.warmup, runs=args.runs)
            hash_res[label] = h_stat
            print(f"  {label:8s} -> Median: {h_stat['median_ms']:.3f} ms, P95: {h_stat['p95_ms']:.3f} ms")
        results["artifact_hash"] = hash_res

        # 3. Crypto Sign & Verify
        print("\n[3/5] Benchmarking Pure Crypto Sign & Verify over Manifest...")
        dummy_manifest = b'{"schema":"minisign-manifest/v1","package":"bench","version":"1.0","algorithm":"algo","keyid":"00","artifact":{"name":"a","size":100,"sha256":"00"}}'
        crypto_res = {}
        for algo in SUPPORTED_ALGORITHMS:
            s_stat, v_stat = measure_crypto_sign_verify(algo, dummy_manifest, warmup=args.warmup, runs=args.runs)
            crypto_res[algo] = {"sign": s_stat, "verify": v_stat}
            print(f"  {algo:18s} -> Sign Median: {s_stat['median_ms']:.3f} ms (P95: {s_stat['p95_ms']:.3f} ms) | Verify Median: {v_stat['median_ms']:.3f} ms (P95: {v_stat['p95_ms']:.3f} ms)")
        results["crypto_ops"] = crypto_res

        # 4. End-to-End CLI Sign
        print("\n[4/5] Benchmarking End-to-End CLI Execution (Sign)...")
        e2e_res = {}
        for algo in SUPPORTED_ALGORITHMS:
            e2e_res[algo] = {}
            for label, path in artifact_paths.items():
                e_stat = measure_end_to_end_cli(algo, path, warmup=args.warmup, runs=args.runs)
                e2e_res[algo][label] = e_stat
                print(f"  {algo:18s} [{label:6s}] -> Median: {e_stat['median_ms']:.3f} ms, P95: {e_stat['p95_ms']:.3f} ms")
        results["e2e_sign"] = e2e_res

        # 5. Sizes
        print("\n[5/5] Measuring Component Sizes...")
        sizes_res = {}
        for algo in SUPPORTED_ALGORITHMS:
            sz = get_sizes(algo, dummy_manifest)
            sizes_res[algo] = sz
            print(f"  {algo:18s} -> PrivKey DER: {sz['priv_key_der_bytes']} B, PubKey DER: {sz['pub_key_der_bytes']} B, Sig Raw: {sz['signature_raw_bytes']} B, Bundle: {sz['bundle_bytes']} B")
        results["sizes"] = sizes_res

    # Output Markdown Report
    with open(args.out, "w") as f:
        f.write("# NoraSign Performance Benchmark Report\n\n")
        f.write(f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- Warmup repetitions: {args.warmup}\n")
        f.write(f"- Measured repetitions: {args.runs}\n")
        f.write("- Percentile metric: P95 calculated via nearest-rank `ceil(0.95 * n)`\n\n")

        f.write("## 1. Key Generation Duration\n\n")
        f.write("| Algorithm | Median (ms) | P95 (ms) |\n")
        f.write("| :--- | :---: | :---: |\n")
        for algo, d in results["keygen"].items():
            f.write(f"| `{algo}` | {d['median_ms']:.3f} | {d['p95_ms']:.3f} |\n")

        f.write("\n## 2. Artifact Hashing (SHA-256)\n\n")
        f.write("| Artifact Size | Median (ms) | P95 (ms) |\n")
        f.write("| :--- | :---: | :---: |\n")
        for sz, d in results["artifact_hash"].items():
            f.write(f"| {sz} | {d['median_ms']:.3f} | {d['p95_ms']:.3f} |\n")

        f.write("\n## 3. Cryptographic Operations (Sign & Verify)\n\n")
        f.write("| Algorithm | Sign Median (ms) | Sign P95 (ms) | Verify Median (ms) | Verify P95 (ms) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for algo, d in results["crypto_ops"].items():
            f.write(f"| `{algo}` | {d['sign']['median_ms']:.3f} | {d['sign']['p95_ms']:.3f} | {d['verify']['median_ms']:.3f} | {d['verify']['p95_ms']:.3f} |\n")

        f.write("\n## 4. End-to-End CLI Sign Execution\n\n")
        f.write("| Algorithm | Artifact Size | Median (ms) | P95 (ms) |\n")
        f.write("| :--- | :--- | :---: | :---: |\n")
        for algo, by_sz in results["e2e_sign"].items():
            for sz, d in by_sz.items():
                f.write(f"| `{algo}` | {sz} | {d['median_ms']:.3f} | {d['p95_ms']:.3f} |\n")

        f.write("\n## 5. Component Sizes in Bytes\n\n")
        f.write("| Algorithm | Private Key DER (B) | Public Key DER (B) | Raw Signature (B) | Bundle JSON (B) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for algo, s in results["sizes"].items():
            f.write(f"| `{algo}` | {s['priv_key_der_bytes']} | {s['pub_key_der_bytes']} | {s['signature_raw_bytes']} | {s['bundle_bytes']} |\n")

    print(f"\nBenchmark completed successfully! Report written to: {args.out}")


if __name__ == "__main__":
    main()
