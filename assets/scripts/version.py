#!/usr/bin/env python3
"""Validate the release version and compute versioned CI artifact identities."""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
VERSION_PATTERN = re.compile(r"1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def read_version(root=ROOT):
    raw = (root / "VERSION").read_bytes().decode("utf-8")
    version = raw.removesuffix("\n")
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("VERSION must be exactly 1.<minor>.<patch>, without leading zeros or suffixes")
    # versioned uses uint64 components. Leave room for an increment.
    if any(int(part) >= 2**64 - 1 for part in version.split(".")):
        raise ValueError("VERSION components must leave room for a versioned increment")
    return version


def check_version(root=ROOT, tag=None):
    version = read_version(root)
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"release tag must equal v{version}")
    return version


def artifact_identity(version, sha, ref_type, ref_name, timestamp=None):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError("invalid artifact version")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("artifact commit must be a full lowercase Git SHA")
    if ref_type == "tag":
        if ref_name != f"v{version}":
            raise ValueError(f"release tag must equal v{version}")
        return f"v{version}"
    if ref_type != "branch":
        raise ValueError("artifact ref type must be branch or tag")
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", stamp):
        raise ValueError("invalid UTC artifact timestamp")
    return f"v{version}_{stamp}_{sha[:12]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "artifact"))
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        version = check_version(tag=args.tag)
        if args.command == "check":
            print(f"Version {version} is valid")
        else:
            sha = os.environ.get("GITHUB_SHA") or subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            artifact = artifact_identity(
                version, sha, os.environ.get("GITHUB_REF_TYPE", "branch"),
                os.environ.get("GITHUB_REF_NAME", ""))
            print(artifact)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                    output.write(f"version={version}\nartifact_id={artifact}\n")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Version check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
