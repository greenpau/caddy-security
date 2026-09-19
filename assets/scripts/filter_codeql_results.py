#!/usr/bin/env python3
"""Apply reviewed CodeQL fingerprints while preserving raw analysis and an audit."""

import argparse
import copy
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / ".github/codeql/suppressions.json"


def load_policy(path):
    policy = json.loads(path.read_text())
    if policy.get("version") != 1 or not isinstance(policy.get("approvals"), list):
        raise ValueError("unsupported CodeQL suppression policy")
    seen_ids, seen_matches = set(), set()
    for item in policy["approvals"]:
        fields = ("review_id", "rule_id", "path", "primary_location_line_hash", "reason")
        if not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not item[k].strip() for k in fields):
            raise ValueError("each suppression requires an ID, exact rule/path/fingerprint and reason")
        path = PurePosixPath(item["path"])
        if (path.is_absolute() or ".." in path.parts or str(path) != item["path"]
                or any(c in item["path"] for c in "*?[]\\:%")):
            raise ValueError("suppression paths must be exact repository-relative paths")
        if not re.fullmatch(r"[a-z0-9/_.-]+", item["rule_id"]):
            raise ValueError("suppression rules must be exact rule IDs")
        if not re.fullmatch(r"[0-9a-f]{16}:[1-9][0-9]*", item["primary_location_line_hash"]):
            raise ValueError("suppression requires a CodeQL primaryLocationLineHash")
        key = (item["rule_id"], item["path"], item["primary_location_line_hash"])
        if item["review_id"] in seen_ids or key in seen_matches:
            raise ValueError("duplicate suppression ID or match")
        seen_ids.add(item["review_id"])
        seen_matches.add(key)
    return policy["approvals"]


def result_key(result):
    locations = result.get("locations", [])
    if len(locations) != 1:
        return None
    artifact = locations[0].get("physicalLocation", {}).get("artifactLocation", {})
    # Match CodeQL's source-root-relative representation only. Unknown bases,
    # absolute URIs, missing fingerprints and changed locations stay visible.
    if artifact.get("uriBaseId") not in (None, "%SRCROOT%"):
        return None
    return (result.get("ruleId"), artifact.get("uri"),
            result.get("partialFingerprints", {}).get("primaryLocationLineHash"))


def filter_results(sarif, approvals):
    if sarif.get("version") != "2.1.0" or not sarif.get("runs"):
        raise ValueError("expected SARIF 2.1.0 with analysis runs")
    filtered = copy.deepcopy(sarif)
    matches = {(p["rule_id"], p["path"], p["primary_location_line_hash"]): p for p in approvals}
    audit = {"input_results": 0, "suppressed_results": 0, "remaining_results": 0,
             "matches": [], "unmatched_approval_ids": []}
    matched = set()
    for index, run in enumerate(filtered["runs"]):
        invocations = run.get("invocations", [])
        if not invocations or any(i.get("executionSuccessful") is not True for i in invocations):
            raise ValueError("cannot filter incomplete or unsuccessful analysis")
        kept = []
        for result in run.get("results", []):
            audit["input_results"] += 1
            approval = matches.get(result_key(result))
            if approval is None:
                kept.append(result)
                continue
            matched.add(approval["review_id"])
            audit["matches"].append({**approval, "run_index": index, "locations": result["locations"]})
        run["results"] = kept
        audit["remaining_results"] += len(kept)
    audit["suppressed_results"] = len(audit["matches"])
    audit["unmatched_approval_ids"] = sorted(p["review_id"] for p in approvals if p["review_id"] not in matched)
    return filtered, audit


def results_csv(sarif):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["Rule", "Level", "Path", "Line", "Column", "Message"])
    for run in sarif["runs"]:
        rules = {}
        for component in [run["tool"]["driver"], *run["tool"].get("extensions", [])]:
            rules.update({r["id"]: r for r in component.get("rules", [])})
        for result in run.get("results", []):
            rule_id = result.get("ruleId", result.get("rule", {}).get("id", ""))
            level = result.get("level", rules.get(rule_id, {}).get("defaultConfiguration", {}).get("level", ""))
            for location in result.get("locations", [{}]):
                physical = location.get("physicalLocation", {})
                region = physical.get("region", {})
                writer.writerow([rule_id, level, physical.get("artifactLocation", {}).get("uri", ""),
                                 region.get("startLine", ""), region.get("startColumn", ""),
                                 result.get("message", {}).get("text", "")])
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="raw SARIF file or directory of .sarif files")
    parser.add_argument("--output-dir", type=Path, required=True, help="reviewed evidence inside this checkout")
    args = parser.parse_args()
    try:
        output = args.output_dir.resolve()
        if ROOT not in output.parents:
            raise ValueError("reviewed CodeQL output must be strictly inside this checkout")
        inputs = sorted(args.input.glob("*.sarif")) if args.input.is_dir() else [args.input]
        if not inputs or any(not p.is_file() or p.suffix != ".sarif" for p in inputs):
            raise ValueError("no raw SARIF inputs found")
        approvals = load_policy(POLICY)
        artifacts, audits = {}, []
        for path in inputs:
            raw = path.read_bytes()
            filtered, audit = filter_results(json.loads(raw), approvals)
            audit.update(input_file=str(path.resolve()), input_sha256=hashlib.sha256(raw).hexdigest(),
                         policy_sha256=hashlib.sha256(POLICY.read_bytes()).hexdigest())
            artifacts[path.name] = json.dumps(filtered, indent=2) + "\n"
            artifacts[path.stem + ".csv"] = results_csv(filtered)
            artifacts[path.stem + ".suppressions.json"] = json.dumps(audit, indent=2) + "\n"
            audits.append((path.name, audit))
        # Validate the whole batch before writing. Exclusive creation also
        # protects earlier evidence if another process races publication.
        if any((output / name).exists() or (output / name).is_symlink() for name in artifacts):
            raise ValueError("reviewed CodeQL evidence already exists; choose a fresh output directory")
        output.mkdir(parents=True, exist_ok=True)
        for name, content in artifacts.items():
            with (output / name).open("x", encoding="utf-8", newline="") as stream:
                stream.write(content)
        for name, audit in audits:
            print(f"{name}: {audit['input_results']} raw, {audit['suppressed_results']} approved suppressions, "
                  f"{audit['remaining_results']} remaining")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"CodeQL filtering failed: {error}\n")


if __name__ == "__main__":
    main()
