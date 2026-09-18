"""Opt-in CI artifact units and real CLI/encryption/cancellation journeys."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "assets/scripts"))
import oidc_conformance_ci as ci


class CITests(unittest.TestCase):
    def setUp(self):
        # Fixture reports must never append to the real Actions job summary.
        env = {k: v for k, v in os.environ.items()
               if k != "GITHUB_STEP_SUMMARY" and not k.startswith("OIDC_CI_")}
        environment = mock.patch.dict(os.environ, env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
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
        page = ci.render_public(summary, True, "<script>alert(1)</script>")
        self.assertNotIn("<script>", page)
        for outcome in ci.OUTCOMES:
            self.assertIn(outcome, page)
        self.assertIn('href="evidence.tar.gz.age"', page)

    def test_workspace_rejects_dependencies_existing_runs_and_symlink_escapes(self):
        for path in (ROOT, ROOT / "tmp", ci.WORK, ci.WORK / "suite", ci.WORK / "tools/age"):
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
        with mock.patch.object(ci, "encrypt_evidence"):
            self.assertEqual(ci.package(self.run, ci.AGE), 2)
        summary = json.loads((self.run / "artifact/summary.json").read_text())
        self.assertEqual(summary["state"], "EVIDENCE_ERROR")
        self.assertFalse(summary["all_passed"])
        self.assertIn("incomplete or unreadable", (self.run / "artifact/index.html").read_text())

    def test_missing_recipient_produces_blocked_report_without_private_upload(self):
        self.record("evidence/execution.json", {"state": "BLOCKED", "blocker": "PRIVATE_SENTINEL"})
        env = os.environ.copy()
        env.pop("OIDC_CONFORMANCE_AGE_RECIPIENT", None)
        result = self.cli("package", env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        files = {p.name for p in (self.run / "artifact").iterdir()}
        self.assertEqual(files, {"index.html", "summary.json", "sha256.json"})
        for file in (self.run / "artifact").iterdir():
            self.assertNotIn("PRIVATE_SENTINEL", file.read_text())
        self.assertIn("OIDC_CONFORMANCE_AGE_RECIPIENT", (self.run / "artifact/index.html").read_text())
        self.assertFalse((self.run / "evidence.tar.gz").exists())

    def test_encryption_failure_never_exposes_partial_archive(self):
        self.record("private-data.json", {"secret": "PRIVATE_SENTINEL"})
        with mock.patch.object(ci, "check_recipient"), \
             mock.patch.object(ci, "recipient", return_value="age1fixture"), \
             mock.patch.object(ci.subprocess, "run", side_effect=[
                 subprocess.CompletedProcess([], 0, "v1.2.1\n"), OSError("PRIVATE_SENTINEL")]), \
             mock.patch.object(ci, "digest", return_value="0" * 64):
            with self.assertRaises(OSError):
                ci.encrypt_evidence(self.run, ci.AGE)
        self.assertFalse((self.run / "evidence.tar.gz").exists())
        self.assertEqual(list((self.run / "artifact").iterdir()), [])

    def test_real_age_roundtrip_preserves_linked_report_and_private_evidence(self):
        # Local conformance does not require age. The manual CI workflow builds
        # the pinned tools before running these opt-in tests.
        age = ci.AGE
        keygen = age.with_name("age-keygen")
        if not age.is_file() or not keygen.is_file():
            self.skipTest("CI archive E2E requires pinned age/age-keygen under tmp/oidc-conformance/tools/age")
        key = self.base / "identity.txt"
        subprocess.run([keygen, "-o", key], capture_output=True, check=True, timeout=10)
        recipient = subprocess.run([keygen, "-y", key], capture_output=True, text=True,
                                   check=True, timeout=10).stdout.strip()
        env = dict(os.environ, OIDC_CONFORMANCE_AGE_RECIPIENT=recipient)
        self.record("evidence/execution.json", {"runner_exit_code": 1, "state": "RUNNER_FINISHED", "all_passed": False})
        self.record("evidence/summary.json", {"modules": [{"name": "oidcc-prompt-login", "outcome": "REVIEW",
                                                          "status": "FINISHED"}]})
        evidence = self.run / "private/evidence"
        (evidence / "index.html").write_text('<a href="trace.json">Private report</a>')
        (evidence / "trace.json").write_bytes(b'PRIVATE_SENTINEL')
        (evidence / "signed-export.zip").write_bytes(b'original signed export fixture')
        result = self.cli("package", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = self.run / "artifact"
        self.assertEqual({p.name for p in artifact.iterdir()},
                         {"index.html", "summary.json", "sha256.json", "evidence.tar.gz.age"})
        for file in artifact.iterdir():
            self.assertNotIn(b"PRIVATE_SENTINEL", file.read_bytes())
        summary = json.loads((artifact / "summary.json").read_text())
        self.assertEqual(summary["runner_exit_code"], 1)
        self.assertFalse(summary["all_passed"])
        hashes = json.loads((artifact / "sha256.json").read_text())
        for name, expected in hashes.items():
            self.assertEqual(ci.digest(artifact / name), expected)
        decrypted = self.base / "decrypted.tar.gz"
        subprocess.run([age, "--decrypt", "-i", key, "-o", decrypted, artifact / "evidence.tar.gz.age"],
                       capture_output=True, check=True, timeout=15)
        with tarfile.open(decrypted) as archive:
            self.assertEqual(archive.extractfile("private/evidence/index.html").read(), (evidence / "index.html").read_bytes())
            self.assertEqual(archive.extractfile("private/evidence/trace.json").read(), b'PRIVATE_SENTINEL')
            self.assertEqual(archive.extractfile("private/evidence/signed-export.zip").read(), b'original signed export fixture')

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
