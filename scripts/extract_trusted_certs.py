#!/usr/bin/env python3
"""
DoctorG Trusted Publisher Certificate Extractor.

Extracts real lowercase SHA-256 signing certificate fingerprints (including APK
Signature Scheme v3 signing lineage / rotation history when available via apksigner)
from a clean, trusted Android device over ADB and updates trusted_publishers.json.

Usage:
  python3 scripts/extract_trusted_certs.py \
    --input app/src/main/assets/trusted_publishers.json \
    --output app/src/main/assets/trusted_publishers.json

  # Or inspect specific extra packages:
  python3 scripts/extract_trusted_certs.py --packages com.google.android.gms com.whatsapp
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SHA256_RE = re.compile(r"SHA-256(?:\s+digest)?:\s*([0-9a-fA-F:]{64,95})")


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def get_base_apk_path(package_name: str, serial: str | None) -> str | None:
    adb = ["adb"] + (["-s", serial] if serial else [])
    rc, out, _ = run_cmd(adb + ["shell", "pm", "path", package_name])
    if rc != 0 or not out.strip():
        return None
    paths = [line.removeprefix("package:").strip() for line in out.splitlines() if line.startswith("package:")]
    for p in paths:
        if p.endswith("base.apk"):
            return p
    return paths[0] if paths else None


def extract_certs_from_apk(apk_path: Path) -> list[str]:
    hashes: list[str] = []
    apksigner = shutil.which("apksigner")
    if apksigner:
        rc, out, _ = run_cmd([apksigner, "verify", "--print-certs", "-v", str(apk_path)])
        if rc == 0:
            for match in SHA256_RE.findall(out):
                digest = match.replace(":", "").lower()
                if len(digest) == 64 and digest not in hashes:
                    hashes.append(digest)
            if hashes:
                return hashes

    keytool = shutil.which("keytool")
    if keytool:
        rc, out, _ = run_cmd([keytool, "-printcert", "-jarfile", str(apk_path)])
        if rc == 0:
            for match in SHA256_RE.findall(out):
                digest = match.replace(":", "").lower()
                if len(digest) == 64 and digest not in hashes:
                    hashes.append(digest)
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract real APK signing cert SHA-256 hashes via ADB.")
    parser.add_argument("--input", default="app/src/main/assets/trusted_publishers.json", help="Input JSON file")
    parser.add_argument("--output", default="", help="Output JSON file (prints to stdout if omitted)")
    parser.add_argument("--serial", default=None, help="Optional ADB device serial")
    parser.add_argument("--packages", nargs="*", default=[], help="Extra package names to inspect")
    args = parser.parse_args()

    if not shutil.which("adb"):
        print("Error: adb not found on PATH.", file=sys.stderr)
        return 1

    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8")) if input_path.exists() else {
        "schemaVersion": 1,
        "version": "2026.11.02",
        "publishers": [],
    }

    by_pkg = {entry["packageName"]: entry for entry in data.get("publishers", [])}
    for pkg in args.packages:
        if pkg not in by_pkg:
            entry = {
                "packageName": pkg,
                "displayName": pkg,
                "certSha256": [],
                "publisher": "Unknown",
                "category": "Custom",
            }
            data["publishers"].append(entry)
            by_pkg[pkg] = entry

    adb = ["adb"] + (["-s", args.serial] if args.serial else [])
    with tempfile.TemporaryDirectory(prefix="doctorg_certs_") as tmp_dir:
        for entry in data.get("publishers", []):
            pkg = entry["packageName"]
            remote_apk = get_base_apk_path(pkg, args.serial)
            if not remote_apk:
                print(f"[SKIP] {pkg}: not installed on device", file=sys.stderr)
                continue
            local_apk = Path(tmp_dir) / f"{pkg}.apk"
            rc, _, err = run_cmd(adb + ["pull", remote_apk, str(local_apk)])
            if rc != 0:
                print(f"[WARN] {pkg}: failed to pull {remote_apk} ({err.strip()})", file=sys.stderr)
                continue
            certs = extract_certs_from_apk(local_apk)
            if certs:
                existing = [c.lower() for c in entry.get("certSha256", [])]
                merged = list(dict.fromkeys(existing + certs))
                entry["certSha256"] = merged
                print(f"[OK]   {pkg}: {len(merged)} SHA-256 cert(s)", file=sys.stderr)
            else:
                print(f"[WARN] {pkg}: could not extract certs (ensure apksigner or keytool is installed)", file=sys.stderr)

    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Wrote updated allowlist to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
