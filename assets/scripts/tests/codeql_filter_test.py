"""Reviewed CodeQL exceptions, retained alerts, and the real filtering CLI."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "assets/scripts/filter_codeql_results.py"
spec = importlib.util.spec_from_file_location("codeql_filter", SCRIPT)
filtering = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filtering)


def finding(approval):
    return {"ruleId": approval["rule_id"], "message": {"text": "synthetic finding"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": approval["path"], "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 42}}}],
            "partialFingerprints": {"primaryLocationLineHash": approval["primary_location_line_hash"]}}


def sarif(results):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "unrelated-rule"}]}},
        "invocations": [{"executionSuccessful": True}], "results": results,
        "automationDetails": {"id": "/language:fixture"}, "properties": {"preserve": True}}]}


class CodeQLFilterTests(unittest.TestCase):
    def setUp(self):
        self.approvals = filtering.load_policy(filtering.POLICY)

    def test_only_four_approved_findings_are_removed_and_audited(self):
        self.assertEqual({p["review_id"] for p in self.approvals}, {"CQ-001", "CQ-002", "CQ-004", "CQ-005"})
        raw = sarif([finding(p) for p in self.approvals])
        original = copy.deepcopy(raw)
        reviewed, audit = filtering.filter_results(raw, self.approvals)
        self.assertEqual(raw, original)
        self.assertEqual(reviewed["runs"][0]["results"], [])
        self.assertEqual(audit["suppressed_results"], 4)
        self.assertEqual(audit["remaining_results"], 0)
        self.assertEqual(audit["unmatched_approval_ids"], [])
        for key in ("tool", "invocations", "properties", "automationDetails"):
            self.assertEqual(reviewed["runs"][0][key], raw["runs"][0][key])
        self.assertEqual({m["reason"] for m in audit["matches"]}, {p["reason"] for p in self.approvals})

    def test_neighboring_rules_files_fingerprints_and_unknown_locations_remain(self):
        for approval in self.approvals:
            base = finding(approval)
            neighbors = []
            other = copy.deepcopy(base)
            other["ruleId"] = "unrelated/rule"
            neighbors.append(other)
            for path in ["nested/" + approval["path"], approval["path"] + ".other",
                         "/" + approval["path"], "file:///" + approval["path"]]:
                other = copy.deepcopy(base)
                other["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = path
                neighbors.append(other)
            for fingerprint in ["0000000000000000:1", approval["primary_location_line_hash"].split(":")[0] + ":2", None]:
                other = copy.deepcopy(base)
                other["partialFingerprints"] = {} if fingerprint is None else {"primaryLocationLineHash": fingerprint}
                neighbors.append(other)
            other = copy.deepcopy(base)
            other["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "UNKNOWN"
            neighbors.append(other)
            for locations in [[], base["locations"] * 2]:
                other = copy.deepcopy(base)
                other["locations"] = locations
                neighbors.append(other)
            reviewed, audit = filtering.filter_results(sarif(neighbors), self.approvals)
            self.assertEqual(reviewed["runs"][0]["results"], neighbors)
            self.assertEqual(audit["suppressed_results"], 0)

    def test_line_movement_preserves_the_reviewed_fingerprint(self):
        result = finding(self.approvals[0])
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 999
        _, audit = filtering.filter_results(sarif([result]), self.approvals)
        self.assertEqual(audit["suppressed_results"], 1)

    def test_remediated_action_rule_is_never_suppressed(self):
        result = finding(self.approvals[0])
        result["ruleId"] = "actions/unpinned-tag"
        reviewed, audit = filtering.filter_results(sarif([result]), self.approvals)
        self.assertEqual(reviewed["runs"][0]["results"], [result])
        self.assertEqual(audit["suppressed_results"], 0)

    def test_failed_or_missing_analysis_metadata_cannot_be_published(self):
        for invocations in [[], [{"executionSuccessful": False}], [{}]]:
            data = sarif([])
            data["runs"][0]["invocations"] = invocations
            with self.assertRaises(ValueError):
                filtering.filter_results(data, self.approvals)

    def test_csv_only_contains_remaining_results(self):
        accepted = finding(self.approvals[0])
        retained = copy.deepcopy(accepted)
        retained["ruleId"] = "visible/rule"
        reviewed, _ = filtering.filter_results(sarif([accepted, retained]), self.approvals)
        csv = filtering.results_csv(reviewed)
        self.assertIn("visible/rule", csv)
        self.assertNotIn(accepted["ruleId"], csv)

    def test_real_cli_retains_raw_evidence_and_rejects_overwrite_and_escape(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="codeql filter ", dir=ROOT / "tmp") as directory:
            root = Path(directory) / "checkout"
            for name in ["assets/scripts/filter_codeql_results.py", ".github/codeql/suppressions.json"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, path)
            source = root / "raw/input.sarif"
            source.parent.mkdir()
            retained = finding(self.approvals[0])
            retained["ruleId"] = "retained/rule"
            source.write_text(json.dumps(sarif([finding(self.approvals[0]), retained])))
            original = source.read_bytes()
            destination = root / "reviewed evidence"

            def command(output, input_path=source):
                return subprocess.run([sys.executable, str(root / "assets/scripts/filter_codeql_results.py"),
                                       "--input", str(input_path), "--output-dir", str(output)],
                                      cwd=directory, capture_output=True, text=True, timeout=10)

            result = command(destination, source.parent)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(source.read_bytes(), original)
            reviewed = json.loads((destination / "input.sarif").read_text())
            self.assertEqual(reviewed["runs"][0]["results"], [retained])
            audit = json.loads((destination / "input.suppressions.json").read_text())
            self.assertEqual(audit["suppressed_results"], 1)
            self.assertEqual(audit["matches"][0]["review_id"], "CQ-001")
            self.assertTrue(audit["input_sha256"] and audit["policy_sha256"])
            self.assertIn("retained/rule", (destination / "input.csv").read_text())
            before = (destination / "input.sarif").read_bytes()
            self.assertNotEqual(command(destination).returncode, 0)
            self.assertEqual((destination / "input.sarif").read_bytes(), before)
            outside = Path(directory) / "outside"
            (root / "escape").symlink_to(outside, target_is_directory=True)
            self.assertNotEqual(command(root / "escape").returncode, 0)
            self.assertFalse(outside.exists())
            self.assertNotEqual(command(root).returncode, 0)
            empty = root / "empty"
            empty.mkdir()
            self.assertNotEqual(command(root / "missing-output", empty).returncode, 0)
            self.assertFalse((root / "missing-output").exists())
            # Invalid policies and unsuccessful input must stop before publishing.
            policy = root / ".github/codeql/suppressions.json"
            for change in [lambda p: p[0].update(path="**/file.go"),
                           lambda p: p[0].update(reason=""),
                           lambda p: p.append(p[0])]:
                approvals = copy.deepcopy(self.approvals)
                change(approvals)
                policy.write_text(json.dumps({"version": 1, "approvals": approvals}))
                self.assertNotEqual(command(root / "invalid").returncode, 0)
                self.assertFalse((root / "invalid").exists())


if __name__ == "__main__":
    unittest.main()
