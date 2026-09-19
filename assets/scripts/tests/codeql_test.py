"""Local CodeQL command failures and checkout/output isolation."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "run_codeql_scan.sh"
FAKE_CODEQL = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

operation = "version" if sys.argv[1] == "version" else " ".join(sys.argv[1:3])
with open(os.environ["CODEQL_TEST_CALLS"], "a") as log:
    log.write(json.dumps({"operation": operation, "args": sys.argv[1:], "cwd": os.getcwd()}) + "\\n")
if operation == os.environ.get("CODEQL_TEST_FAIL"):
    sys.exit(23)
if operation == "database create":
    Path(sys.argv[3]).mkdir()
elif operation in ("database analyze", "database interpret-results"):
    output = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--output="))
    if operation == "database analyze":
        report = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}},
                  "invocations": [{"executionSuccessful": True}], "results": []}]}
        Path(output).write_text(json.dumps(report))
    else:
        Path(output).write_text("synthetic raw CSV")
'''


class CodeQLScanTests(unittest.TestCase):
    def setUp(self):
        workspace = SCRIPT.parents[2] / "tmp"
        workspace.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="caddy-security codeql ", dir=workspace)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.script = self.root / "checkout/assets/scripts/run_codeql_scan.sh"
        self.script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.script)
        for name in ("assets/scripts/filter_codeql_results.py", ".github/codeql/suppressions.json"):
            source = SCRIPT.parents[2] / name
            destination = self.root / "checkout" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        self.codeql = self.root / "fake codeql"
        self.codeql.write_text(FAKE_CODEQL)
        self.codeql.chmod(0o755)
        self.calls = self.root / "calls"
        self.env = {**os.environ, "CODEQL": str(self.codeql),
                    "CODEQL_TEST_CALLS": str(self.calls), "CODEQL_OUTPUT_DIR": "reports with spaces"}
        self.env.pop("CODEQL_TEST_FAIL", None)
        self.env.pop("CODEQL_LANGUAGE", None)
        self.output = self.root / "checkout/reports with spaces"

    def command(self):
        return subprocess.run(["bash", str(self.script)], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=10)

    def recorded_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_e2e_scan_uses_own_checkout_and_quoted_output_paths(self):
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output / "results.sarif").is_file())
        self.assertTrue((self.output / "results.csv").is_file())
        self.assertTrue((self.output / "raw/results.sarif").is_file())
        self.assertTrue((self.output / "raw/results.csv").is_file())
        self.assertTrue((self.output / "results.suppressions.json").is_file())
        self.assertFalse((self.root / "reports with spaces").exists())
        calls = self.recorded_calls()
        self.assertTrue(all(Path(call["cwd"]) == self.root / "checkout" for call in calls))
        create = next(call for call in calls if call["operation"] == "database create")
        self.assertIn(f"--source-root={self.root / 'checkout'}", create["args"])
        self.assertIn(f"--codescanning-config={self.root / 'checkout/.github/codeql/codeql-config.yml'}",
                      create["args"])
        self.assertIn("--command=go build -mod=readonly ./...", create["args"])
        self.assertTrue((self.output / "scan.log").exists())

    def test_interpreted_languages_do_not_build_go(self):
        for language in ("python", "actions", "javascript-typescript"):
            with self.subTest(language=language):
                self.env["CODEQL_LANGUAGE"] = language
                self.env["CODEQL_OUTPUT_DIR"] = language
                result = self.command()
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.recorded_calls()
                create = next(call for call in calls if call["operation"] == "database create")
                self.assertIn(f"--language={language}", create["args"])
                self.assertFalse(any(arg.startswith("--command=") for arg in create["args"]))
                pack = next(call for call in calls if call["operation"] == "pack download")
                pack_language = "javascript" if language == "javascript-typescript" else language
                self.assertIn(f"codeql/{pack_language}-queries", pack["args"])
                self.calls.unlink()

    def test_default_output_is_unique_and_preserves_previous_evidence(self):
        self.env.pop("CODEQL_OUTPUT_DIR")
        for _ in range(2):
            result = self.command()
            self.assertEqual(result.returncode, 0, result.stderr)
        outputs = list((self.root / "checkout/.coverage/codeql").glob("go-scan.*"))
        self.assertEqual(len(outputs), 2)
        self.assertTrue(all((path / "results.sarif").exists() for path in outputs))

    def test_existing_evidence_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "results.sarif"
        marker.write_text("original evidence")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new or empty directory", result.stderr)
        self.assertEqual(marker.read_text(), "original evidence")
        self.assertFalse(self.calls.exists())

    def test_output_cannot_escape_checkout_or_target_its_root(self):
        outside = self.root / "outside"
        (self.root / "checkout/escape").symlink_to(outside, target_is_directory=True)
        for destination in (str(outside / "new"), "../outside", ".", "escape/nested"):
            with self.subTest(destination=destination):
                self.env["CODEQL_OUTPUT_DIR"] = destination
                result = self.command()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("strictly inside this checkout", result.stderr)
                self.assertFalse(outside.exists())
                self.assertFalse(self.calls.exists())

    def test_default_output_cannot_escape_through_symlink(self):
        outside = self.root / "outside"
        (self.root / "checkout/.coverage").symlink_to(outside, target_is_directory=True)
        self.env.pop("CODEQL_OUTPUT_DIR")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(outside.exists())
        self.assertFalse(self.calls.exists())

    def test_unsupported_language_fails_before_creating_output(self):
        self.env["CODEQL_LANGUAGE"] = "unsupported"
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported CODEQL_LANGUAGE", result.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_cli_fails_without_creating_reports(self):
        self.env["CODEQL"] = str(self.root / "missing cli")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CodeQL CLI not found", result.stderr)
        self.assertFalse(self.output.exists())

    def test_command_failure_is_preserved_and_stops_following_steps(self):
        operations = ["version", "pack download", "database create",
                      "database analyze", "database interpret-results"]
        for index, operation in enumerate(operations):
            with self.subTest(operation=operation):
                self.calls.unlink(missing_ok=True)
                if self.output.exists():
                    shutil.rmtree(self.output)
                self.env["CODEQL_TEST_FAIL"] = operation
                result = self.command()
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual([call["operation"] for call in self.recorded_calls()], operations[:index + 1])
                self.assertNotIn("CodeQL scan results:", result.stdout)
                self.assertFalse((self.output / "results.csv").exists())

    def test_filter_failure_stops_scan_and_preserves_raw_evidence(self):
        policy = self.root / "checkout/.github/codeql/suppressions.json"
        policy.write_text("invalid JSON")
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CodeQL scan results:", result.stdout)
        self.assertTrue((self.output / "raw/results.sarif").is_file())
        self.assertFalse((self.output / "results.sarif").exists())


if __name__ == "__main__":
    unittest.main()
