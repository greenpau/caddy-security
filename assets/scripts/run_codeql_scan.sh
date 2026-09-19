#!/bin/bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
codeql_cmd="${CODEQL:-codeql}"
if ! command -v "$codeql_cmd" >/dev/null 2>&1; then
  printf 'CodeQL CLI not found: %s\n' "$codeql_cmd" >&2
  exit 1
fi

language="${CODEQL_LANGUAGE:-go}"
case "$language" in
  go|python|actions) pack_language="$language" ;;
  javascript-typescript) pack_language=javascript ;;
  *) printf 'Unsupported CODEQL_LANGUAGE: %s (use go, javascript-typescript, python or actions)\n' "$language" >&2; exit 1 ;;
esac

# Resolve symlinks before creating anything, including a custom output parent.
# A scan must never write into a sibling checkout or reuse earlier evidence.
output_dir="$("${PYTHON:-python3}" - "$repo_root" "${CODEQL_OUTPUT_DIR:-}" "$language" <<'PY'
from pathlib import Path
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve() if sys.argv[2] else (root / '.coverage/codeql').resolve()
if root not in output.parents:
    raise SystemExit('CodeQL output must be strictly inside this checkout')
if sys.argv[2]:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise SystemExit('CodeQL output must be a new or empty directory')
    output.mkdir(parents=True, exist_ok=True)
else:
    output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=sys.argv[3] + '-scan.', dir=output))
print(output)
PY
)"
printf 'CodeQL scan evidence: %s\n' "$output_dir"

run_scan() {
  mkdir "$output_dir/raw"
  "$codeql_cmd" version --format=json > "$output_dir/codeql-version.json"
  "$codeql_cmd" pack download "codeql/$pack_language-queries"
  create_args=(--language="$language" --source-root="$repo_root"
    --codescanning-config="$repo_root/.github/codeql/codeql-config.yml")
  if [[ "$language" == go ]]; then
    create_args+=(--command='go build -mod=readonly ./...')
  fi
  "$codeql_cmd" database create "$output_dir/database" "${create_args[@]}"
  "$codeql_cmd" database analyze "$output_dir/database" \
    --threads=2 --ram=5922 --format=sarif-latest \
    --sarif-category="/language:$language" --output="$output_dir/raw/results.sarif"
  "$codeql_cmd" database interpret-results "$output_dir/database" \
    --format=csv --output="$output_dir/raw/results.csv"
  "${PYTHON:-python3}" assets/scripts/filter_codeql_results.py \
    --input "$output_dir/raw/results.sarif" --output-dir "$output_dir"
}

# pipefail preserves a failed stage while tee retains diagnostics for review.
# Do not invoke run_scan as an if/OR condition: that disables Bash errexit inside it.
run_scan 2>&1 | tee "$output_dir/scan.log"
printf 'CodeQL scan results: %s\n' "$output_dir"
