"""Opt-in CI artifact units and real CLI/download/cancellation journeys."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "assets/scripts"))
import oidc_conformance_ci as ci


class CITests(unittest.TestCase):
    def setUp(self):
        # Fixture reports must never append to the real Actions job summary.
        env = {k: v for k, v in os.environ.items()
               if k not in ("GITHUB_STEP_SUMMARY", "OIDC_CONFORMANCE_AGE_RECIPIENT")
               and not k.startswith("OIDC_CI_")}
        environment = mock.patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="oidc-ci-test-", dir=ROOT / "tmp")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.run = self.base / "run"
        ci.initialize(self.run)
        self.script = ROOT / "assets/scripts/oidc_conformance_ci.py"

    def cli(self, *args, **kwargs):
        return subprocess.run([sys.executable, self.script, "--workspace", self.run, *args],
                              capture_output=True, text=True, timeout=120, **kwargs)

    def record(self, path, value):
        target = self.run / "private" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def test_public_summary_omits_private_fields_and_keeps_every_outcome_and_attempt(self):
        self.record("evidence/execution.json", {"runner_exit_code": 1, "state": "EVIDENCE_ERROR",
                                              "blocker": "PRIVATE_SENTINEL", "all_passed": False})
        modules = [{"name": "oidcc-prompt-login", "outcome": o, "status": "FINISHED",
                    "nonpass_events": [{"secret": "PRIVATE_SENTINEL"}]} for o in ci.OUTCOMES]
        modules.append(dict(modules[0]))
        self.record("evidence/summary.json", {"modules": modules, "secret": "PRIVATE_SENTINEL"})
        self.record("evidence/candidate.json", {"commit": "a" * 40, "private": "PRIVATE_SENTINEL"})
        summary = ci.public_summary(self.run)
        self.assertEqual(summary["runner_exit_code"], 1)
        self.assertFalse(summary["all_passed"])
        self.assertTrue(summary["evidence_has_blocker"])
        self.assertEqual(len(summary["modules"]), 8)
        self.assertEqual(summary["counts"]["PASSED"], 2)
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(summary))
        summary.update(evidence_directory="private/", full_report="private/evidence/index.html")
        page = ci.render_public(summary, "<script>alert(1)</script>")
        self.assertNotIn("<script>", page)
        for outcome in ci.OUTCOMES:
            self.assertIn(outcome, page)
        self.assertIn('href="private/evidence/index.html"', page)

    def test_workspace_rejects_dependencies_existing_runs_and_symlink_escapes(self):
        for path in (ROOT, ROOT / "tmp", ci.WORK, ci.WORK / "suite", ci.WORK / "tools/chrome"):
            with self.subTest(path=path), self.assertRaises((ValueError, ci.ArtifactError)):
                ci.workspace(path)
        link = self.base / "escape"
        link.symlink_to(ROOT, target_is_directory=True)
        with self.assertRaises(ci.ArtifactError):
            ci.workspace(link / "evidence")
        with self.assertRaises(FileExistsError):
            ci.initialize(self.run)

    def test_failed_cli_stage_preserves_exit_and_keeps_log_private(self):
        result = self.cli("stage", "--timeout", "10", "test", "--", sys.executable,
                          "-c", "print('PRIVATE_SENTINEL'); raise SystemExit(7)")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("PRIVATE_SENTINEL", result.stdout + result.stderr)
        record = json.loads((self.run / "private/test.json").read_text())
        self.assertEqual(record["exit_code"], 7)
        self.assertEqual(record["state"], "FAILED")
        log = self.run / "private/test.log"
        self.assertIn("PRIVATE_SENTINEL", log.read_text())
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_stage_timeout_stops_child_and_keeps_interruption(self):
        pid_file = self.base / "child.pid"
        source = ("import os,time; from pathlib import Path; "
                  f"Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)")
        result = self.cli("stage", "--timeout", "1", "prepare", "--", sys.executable, "-c", source)
        diagnostic = self.run / "private/ci-error.log"
        self.assertEqual(result.returncode, 124, result.stderr + (diagnostic.read_text() if diagnostic.exists() else ""))
        record = json.loads((self.run / "private/prepare.json").read_text())
        self.assertEqual(record["exit_code"], -signal.SIGTERM)
        self.assertTrue(record["timed_out"])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_transient_group_probe_permission_error_still_waits_for_exit(self):
        child = mock.Mock(pid=42)
        with mock.patch.object(ci.os, "killpg", side_effect=[None, PermissionError(), ProcessLookupError()]), \
             mock.patch.object(ci.time, "sleep"):
            ci.stop_group(child)
        child.wait.assert_called_once_with(timeout=10)

    def test_sigterm_records_interruption_and_stops_owned_stage(self):
        pid_file = self.base / "interrupted.pid"
        source = ("import os,time; from pathlib import Path; "
                  f"Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(20)")
        child = subprocess.Popen([sys.executable, self.script, "--workspace", self.run,
                                  "stage", "--timeout", "30", "test", "--", sys.executable, "-c", source],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not pid_file.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(pid_file.exists())
            child.terminate()
            self.assertEqual(child.wait(timeout=15), 130)
            record = json.loads((self.run / "private/test.json").read_text())
            self.assertTrue(record["interrupted"])
            self.assertEqual(record["exit_code"], -signal.SIGTERM)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_incomplete_json_still_gets_an_honest_artifact(self):
        (self.run / "private/evidence").mkdir()
        (self.run / "private/evidence/execution.json").write_text('{"runner_exit_code":')
        self.assertEqual(ci.package(self.run), 2)
        summary = json.loads((self.run / "artifact/summary.json").read_text())
        self.assertEqual(summary["state"], "EVIDENCE_ERROR")
        self.assertFalse(summary["all_passed"])
        self.assertEqual(summary["evidence_directory"], "private/")
        self.assertIsNone(summary["full_report"])
        self.assertIn("incomplete or unreadable", (self.run / "artifact/index.html").read_text())
        self.assertEqual((self.run / "artifact/private/evidence/execution.json").read_bytes(), b'{"runner_exit_code":')

    def test_initialize_and_blocked_report_need_no_recipient_or_encryption_tool(self):
        fresh = self.base / "fresh"
        result = subprocess.run([sys.executable, self.script, "--workspace", fresh, "initialize"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((fresh / "private/ci.json").is_file())
        self.record("evidence/execution.json", {"state": "BLOCKED", "blocker": "PRIVATE_SENTINEL"})
        result = self.cli("package")
        self.assertEqual(result.returncode, 0, result.stderr)
        files = {p.name for p in (self.run / "artifact").iterdir()}
        self.assertEqual(files, {"index.html", "summary.json", "sha256.json", "private", "filesystem-entries.json"})
        summary = json.loads((self.run / "artifact/summary.json").read_text())
        self.assertEqual(summary["state"], "BLOCKED")
        self.assertFalse(summary["all_passed"])
        self.assertTrue(summary["evidence_has_blocker"])
        self.assertIsNone(summary["full_report"])
        page = (self.run / "artifact/index.html").read_text()
        self.assertNotIn('href="private/evidence/index.html"', page)
        self.assertIn('href="private/"', page)
        self.assertIn(b"PRIVATE_SENTINEL", (self.run / "artifact/private/evidence/execution.json").read_bytes())

    def test_packaging_failure_removes_partial_and_stale_evidence(self):
        self.record("private-data.json", {"secret": "PRIVATE_SENTINEL"})
        artifact = self.run / "artifact"
        prepared = self.base / "prepared"
        prepared.mkdir()
        (prepared / "suite-build.log").write_text("fixture preparation")
        for method in ("copy2", "copyfile"):
            with self.subTest(failure=method), mock.patch.object(ci, "WORK", prepared), \
                 mock.patch.object(ci.shutil, method, side_effect=OSError("evidence copy failed")):
                (artifact / "stale.html").write_bytes(b'stale report')
                partial = self.run / "artifact.partial"
                partial.mkdir()
                (partial / "interrupted.html").write_bytes(b'interrupted report')
                self.assertEqual(ci.package(self.run), 2)
                self.assertEqual({p.name for p in artifact.iterdir()},
                                 {"index.html", "summary.json", "sha256.json", "package-error.log"})
                self.assertFalse(partial.exists())
                summary = json.loads((artifact / "summary.json").read_text())
                self.assertIsNone(summary["evidence_directory"])
                self.assertIsNone(summary["full_report"])
                self.assertEqual(summary["packaging_exit_code"], 2)
                self.assertNotIn('href="private/"', (artifact / "index.html").read_text())
                self.assertIn('href="package-error.log"', (artifact / "index.html").read_text())
                self.assertIn("evidence copy failed", (artifact / "package-error.log").read_text())
        # A successful retry clears earlier packaging diagnostics as well.
        self.assertEqual(ci.package(self.run), 0)
        self.assertFalse((artifact / "package-error.log").exists())
        self.assertFalse((artifact / "private/package-error.log").exists())

    def test_one_zip_extraction_opens_linked_report_with_original_bytes_and_hashes(self):
        self.record("evidence/execution.json", {"runner_exit_code": 1, "state": "RUNNER_FINISHED", "all_passed": False})
        self.record("evidence/summary.json", {"modules": [{"name": "oidcc-prompt-login", "outcome": "REVIEW",
                                                          "status": "FINISHED"}]})
        evidence = self.run / "private/evidence"
        (evidence / "index.html").write_text('<a href="trace.json">Private report</a>')
        (evidence / "trace.json").write_bytes(b'PRIVATE_SENTINEL')
        (evidence / "signed-export.zip").write_bytes(b'original signed export fixture')
        (evidence / ".hidden-evidence").write_bytes(b'hidden original')
        (evidence / ".hidden-directory").mkdir()
        (evidence / ".hidden-directory/data").write_bytes(b'hidden directory original')
        outside = self.base / "outside-archive.txt"
        outside.write_bytes(b'NEVER_FOLLOW_SYMLINK')
        (evidence / "profile-link").symlink_to(outside)
        (evidence / "profile-directory").symlink_to(self.base, target_is_directory=True)
        (evidence / "broken-link").symlink_to("missing-target")
        os.mkfifo(evidence / "profile-pipe")
        self.record("evidence/evidence-sha256.json", {name: ci.digest(evidence / name)
                    for name in ("index.html", "trace.json", "signed-export.zip", ".hidden-evidence", ".hidden-directory/data")})
        result = self.cli("package")
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = self.run / "artifact"
        self.assertEqual({p.name for p in artifact.iterdir()},
                         {"index.html", "summary.json", "sha256.json", "private", "filesystem-entries.json"})
        summary = json.loads((artifact / "summary.json").read_text())
        self.assertEqual(summary["runner_exit_code"], 1)
        self.assertFalse(summary["all_passed"])
        self.assertEqual(summary["counts"], {"REVIEW": 1})
        self.assertEqual(summary["evidence_directory"], "private/")
        self.assertEqual(summary["full_report"], "private/evidence/index.html")
        hashes = json.loads((artifact / "sha256.json").read_text())
        self.assertEqual(set(hashes), {p.relative_to(artifact).as_posix()
                         for p in artifact.rglob("*") if p.is_file() and p != artifact / "sha256.json"})
        for name, expected in hashes.items():
            self.assertEqual(ci.digest(artifact / name), expected)
        entries = {entry["path"]: entry for entry in json.loads((artifact / "filesystem-entries.json").read_text())}
        self.assertEqual(set(entries), {"private/evidence/" + name for name in
                         ("profile-link", "profile-directory", "broken-link", "profile-pipe")})
        self.assertEqual(entries["private/evidence/profile-link"]["target"], str(outside))
        self.assertEqual(entries["private/evidence/profile-directory"]["target"], str(self.base))
        self.assertEqual(entries["private/evidence/broken-link"]["target"], "missing-target")
        self.assertTrue(entries["private/evidence/profile-pipe"]["mode"].startswith("p"))
        # Model the upload action's single ZIP, including hidden files. There
        # must be no live symlinks for its globber/archiver to follow.
        download = self.base / "download.zip"
        with zipfile.ZipFile(download, "w", zipfile.ZIP_DEFLATED) as archive:
            for file in artifact.rglob("*"):
                self.assertFalse(file.is_symlink())
                if file.is_file():
                    self.assertNotIn(b'NEVER_FOLLOW_SYMLINK', file.read_bytes())
                    archive.write(file, file.relative_to(artifact))
        extracted = self.base / "extracted"
        with zipfile.ZipFile(download) as archive:
            archive.extractall(extracted)
        page = (extracted / "index.html").read_text()
        self.assertIn('href="private/evidence/index.html"', page)
        self.assertNotIn("tar -xzf", page)
        self.assertFalse((extracted / "evidence.tar.gz").exists())
        for name, expected in hashes.items():
            self.assertEqual(ci.digest(extracted / name), expected)
        report = extracted / "private/evidence"
        self.assertIn('href="trace.json"', (report / "index.html").read_text())
        self.assertEqual((report / "signed-export.zip").read_bytes(), b'original signed export fixture')
        self.assertEqual((report / "evidence-sha256.json").read_bytes(), (evidence / "evidence-sha256.json").read_bytes())
        for name, expected in json.loads((report / "evidence-sha256.json").read_text()).items():
            self.assertEqual(ci.digest(report / name), expected)

    def test_preparation_cancellation_unwinds_its_independent_process_session(self):
        # Exercise preparation's real entry point with only the download/build
        # work replaced by a sleeper launched through its actual command helper.
        pid_file = self.base / "owned.pid"
        (self.base / "fixture").mkdir()
        sleeper = "import os,time; from pathlib import Path; " + f"Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)"
        source = ("import sys; from pathlib import Path; "
                  f"sys.path.insert(0, {str(ROOT / 'assets/scripts')!r}); "
                  "import prepare_oidc_conformance as p; "
                  f"p.WORK=Path({str(self.base / 'fixture/tmp/oidc-conformance')!r}); "
                  f"p.prepare=lambda: p.command([sys.executable, '-c', {sleeper!r}]); p.main([])")
        child = subprocess.Popen([sys.executable, "-c", source], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not pid_file.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(pid_file.exists())
            child.terminate()
            self.assertNotEqual(child.wait(timeout=15), 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
