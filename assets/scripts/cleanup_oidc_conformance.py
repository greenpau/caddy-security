#!/usr/bin/env python3
"""Remove OIDC run bundles and supplemental output, keeping prepared prerequisites."""

import argparse
from pathlib import Path
import subprocess
import sys

from oidc_conformance_artifacts import ArtifactError, cleanup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="list OIDC bundles and supplemental artifacts without removing them")
    for option in ("suite", "java", "mongod", "runner-python"):
        parser.add_argument("--" + option, type=Path, help="retain a custom prerequisite location")
    args = parser.parse_args()
    try:
        cleanup(Path(__file__).resolve().parents[2], args, args.dry_run)
    except (ArtifactError, OSError, subprocess.SubprocessError) as error:
        print("OIDC cleanup blocked: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
