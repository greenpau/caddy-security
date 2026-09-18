"""Opt-in unit and real Make/CLI coverage of OIDC evidence cleanup."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "assets/scripts"))
import oidc_conformance_artifacts as artifacts


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="oidc-conformance-cleanup-", dir=ROOT / "tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.work = self.root / "tmp/oidc-conformance"
        self.work.mkdir(parents=True)

    def bundle(self, name="tmp/oidc-conformance/run-example", legacy=False):
        path = self.root / name
        if legacy:
            path.mkdir(parents=True)
            (path / "execution.json").write_text(json.dumps({
                "suite_revision": "a" * 40, "certification": False, "local_only": False,
                "started_at": "2026-09-17T00:00:00Z", "state": "BLOCKED", "runner_exit_code": None,
            }))
        else:
            artifacts.mark_output(self.root, path, None)
        for name in ("index.html", "exports/signed.zip", "mongodb/data", "runtime/profile/Cookies", "private.key", "caddy.log"):
            target = path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"synthetic private evidence")
        return path

    def clean(self, **kwargs):
        with redirect_stdout(io.StringIO()):
            return artifacts.cleanup(self.root, **kwargs)

    def supplemental(self):
        paths = []
        for name in ("oidc-cleanup-units.log", "oidc-consent-final-audit.json", "oidc-header-adapt.json",
                     "audit_oidc_consent.py", "check_oidc_consent_report.py"):
            path = self.root / "tmp" / name
            path.write_bytes(b"synthetic supplemental output")
            paths.append(path)
        for name in ("oidc-consent-report-ui", "oidc-consent-report-ui-final", "oidc-consent-report-ui-preview"):
            path = self.root / "tmp" / name
            path.mkdir()
            (path / "screenshot.png").write_bytes(b"synthetic screenshot")
            profile = path / "chrome-profile/Default"
            profile.mkdir(parents=True)
            (profile / "Cookies").write_bytes(b"synthetic private profile")
            paths.append(path)
        return paths

    def test_all_owned_runs_and_custom_paths_removed_dependencies_unchanged(self):
        preserved = []
        for name in artifacts.DEPENDENCIES:
            if name in ("oidc-conformance.lock", artifacts.DEPENDENCY_RECORD):
                continue
            target = self.work / name
            if name not in ("prerequisites.json", "suite-build.log"):
                target /= "dependency-bytes"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"retain exactly")
            preserved.append(target)
        unrelated = self.root / "tmp/unrelated/index.html"
        unrelated.parent.mkdir()
        unrelated.write_bytes(b"retain exactly")
        preserved.append(unrelated)
        runs = [self.bundle(), self.bundle("tmp/oidc-conformance/chrome-old", legacy=True),
                self.bundle('tmp/custom reports/quote" and `literal`'), self.bundle("tmp/local-only")]
        (runs[0] / "external-link").symlink_to(unrelated.parent, target_is_directory=True)
        self.assertEqual(set(self.clean()), set(runs))
        self.assertTrue(all(not p.exists() for p in runs))
        for path in preserved:
            self.assertEqual(path.read_bytes(), b"retain exactly")
        self.assertEqual(self.clean(), [])

    def test_loose_logs_audits_helpers_and_browser_reports_removed(self):
        supplemental = self.supplemental()
        run = self.bundle()
        parent = self.root / "tmp/oidc-custom-reports"
        self.bundle("tmp/oidc-custom-reports/run-one")
        preserved = []
        for name in ("tmp/unrelated.log", "tmp/application/oidc-consent.log",
                     "tmp/application/audit_oidc_consent.py", "assets/scripts/oidc-source.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"unrelated output or source")
            preserved.append(path)
        (supplemental[-1] / "outside-link").symlink_to(preserved[1].parent, target_is_directory=True)
        alias = self.root / "tmp/oidc-external-alias"
        alias.symlink_to(preserved[1].parent, target_is_directory=True)
        expected = set(supplemental + [run, parent])
        self.assertEqual(set(self.clean(dry_run=True)), expected)
        self.assertTrue(all(p.exists() for p in expected))
        self.assertEqual(set(self.clean()), expected)
        self.assertTrue(all(not p.exists() for p in expected))
        self.assertTrue(alias.is_symlink())
        self.assertTrue(all(p.read_bytes() == b"unrelated output or source" for p in preserved))
        self.assertEqual(self.clean(), [])

    def test_custom_dependencies_stay_protected_after_run_metadata_deleted(self):
        for recorded in (True, False):
            with self.subTest(recorded=recorded):
                tool = self.root / f"tmp/oidc-custom-java-{recorded}/bin/java"
                tool.parent.mkdir(parents=True)
                tool.write_bytes(b"retain custom prerequisite")
                args = SimpleNamespace(java=tool)
                run = self.root / f"tmp/oidc-conformance/custom-{recorded}"
                artifacts.mark_output(self.root, run, args if recorded else None)
                options = {} if recorded else {"args": args}
                self.assertEqual(self.clean(dry_run=True, **options), [run])
                self.assertEqual(self.clean(**options), [run])
                record = self.work / artifacts.DEPENDENCY_RECORD
                self.assertEqual(record.stat().st_mode & 0o777, 0o600)
                contents = record.read_bytes()
                self.assertEqual(self.clean(), [])
                self.assertEqual(record.read_bytes(), contents)
                self.assertEqual(tool.read_bytes(), b"retain custom prerequisite")
                with self.assertRaisesRegex(artifacts.ArtifactError, "overlap"):
                    artifacts.mark_output(self.root, tool.parent.parent / "run", None)

    def test_custom_dependency_inside_supplemental_directory_blocks_all_deletion(self):
        supplemental = self.supplemental()
        run = self.bundle("tmp/oidc-custom-reports/run-one")
        tool = supplemental[-1] / "tools/bin/java"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"retain custom prerequisite")
        marker = run / artifacts.MARKER
        data = json.loads(marker.read_text())
        data["dependencies"].append(str(tool.parent.parent))
        marker.write_text(json.dumps(data))
        with self.assertRaisesRegex(artifacts.ArtifactError, "overlap"):
            self.clean()
        self.assertTrue(all(p.exists() for p in supplemental + [run, tool]))
        self.assertFalse((self.work / artifacts.DEPENDENCY_RECORD).exists())

    def test_invalid_custom_dependency_record_blocks_cleanup(self):
        supplemental = self.supplemental()
        record = self.work / artifacts.DEPENDENCY_RECORD
        for data in ("null", "{}", "broken"):
            record.write_text(data)
            with self.assertRaisesRegex(artifacts.ArtifactError, "metadata"):
                self.clean()
            self.assertTrue(all(p.exists() for p in supplemental))
        record.unlink()
        record.symlink_to(self.root / "nonexistent")
        with self.assertRaisesRegex(artifacts.ArtifactError, "symlinked"):
            self.clean()
        self.assertTrue(all(p.exists() for p in supplemental))

    def test_dry_run_preserves_evidence(self):
        run = self.bundle()
        self.assertEqual(self.clean(dry_run=True), [run])
        self.assertTrue((run / "private.key").is_file())

    def test_marking_refuses_prerequisites_and_nested_results(self):
        for path in (self.work / "suite/new-run", self.work / "tools/new-run", self.root / "tmp"):
            with self.subTest(path=path), self.assertRaises(artifacts.ArtifactError):
                artifacts.mark_output(self.root, path, None)
        run = self.bundle()
        with self.assertRaisesRegex(artifacts.ArtifactError, "nested"):
            artifacts.mark_output(self.root, run / "nested", None)

    def test_symlink_workspace_or_marker_never_allows_deletion(self):
        run = self.bundle()
        marker = run / artifacts.MARKER
        data = marker.read_bytes()
        marker.unlink()
        elsewhere = self.root / "marker.json"
        elsewhere.write_bytes(data)
        marker.symlink_to(elsewhere)
        with self.assertRaisesRegex(artifacts.ArtifactError, "symlinked"):
            self.clean()
        self.assertTrue((run / "private.key").exists())
        alias = self.root / "tmp/alias"
        alias.symlink_to(run, target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.mark_output(self.root, alias / "child", None)
        other = self.root / "other"
        other.mkdir()
        (other / "tmp").symlink_to(self.root / "tmp", target_is_directory=True)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.cleanup(other)

    def test_custom_dependencies_protected_before_any_deletion(self):
        first, second = self.bundle(), self.bundle("tmp/second")
        marker = first / artifacts.MARKER
        data = json.loads(marker.read_text())
        data["dependencies"].append(str(second / "private.key"))
        marker.write_text(json.dumps(data))
        with self.assertRaisesRegex(artifacts.ArtifactError, "overlap"):
            self.clean()
        self.assertTrue(first.exists() and second.exists())

    def test_active_run_and_preparation_locks_block_cleanup(self):
        run = self.bundle()
        for operation in ("run", "prepare"):
            with artifacts.workspace_lock(self.root, operation):
                with self.assertRaisesRegex(artifacts.ArtifactError, "active"):
                    self.clean()
        self.assertTrue(run.exists())

    def test_live_legacy_process_blocks_entire_cleanup(self):
        run = self.bundle(legacy=True)
        other = self.bundle("tmp/other")
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(run / "mongodb")])
        try:
            with self.assertRaisesRegex(artifacts.ArtifactError, "still used by process"):
                self.clean()
            self.assertTrue(run.exists() and other.exists())
        finally:
            process.terminate()
            process.wait(timeout=5)
        self.assertEqual(set(self.clean()), {run, other})

    def test_live_supplemental_process_blocks_files_and_directories(self):
        supplemental = self.supplemental()
        for path in (supplemental[0], supplemental[-1] / "chrome-profile"):
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(path)])
            try:
                with self.assertRaisesRegex(artifacts.ArtifactError, "still used by process"):
                    self.clean()
                self.assertTrue(all(p.exists() for p in supplemental))
            finally:
                process.terminate()
                process.wait(timeout=5)
        self.assertEqual(set(self.clean()), set(supplemental))

    def test_malformed_metadata_and_process_scan_failure_preserve_evidence(self):
        run = self.bundle()
        marker = run / artifacts.MARKER
        original = marker.read_bytes()
        for value in ("[]", "null", "broken", '{"kind":"unrelated"}'):
            marker.write_text(value)
            with self.assertRaises(artifacts.ArtifactError):
                self.clean()
            self.assertTrue((run / "private.key").is_file())
        marker.write_bytes(original)
        with mock.patch.object(artifacts.subprocess, "run", side_effect=OSError("ps unavailable")):
            with self.assertRaises(OSError):
                self.clean()
        self.assertTrue(run.exists())

    def test_real_make_cleanup_and_subsequent_run_reuse_retained_tools(self):
        # Use the real public recipe in a disposable repository; never erase
        # this checkout's recorded official evidence as a fixture side effect.
        shutil.copy2(ROOT / "Makefile", self.root / "Makefile")
        scripts = self.root / "assets/scripts"
        scripts.mkdir(parents=True)
        for name in ("cleanup_oidc_conformance.py", "oidc_conformance_artifacts.py"):
            shutil.copy2(ROOT / "assets/scripts" / name, scripts / name)
        prerequisites = self.work / "tools/java/bin/java"
        prerequisites.parent.mkdir(parents=True)
        prerequisites.write_text("#!/bin/sh\nprintf 'retained-tool\\n'\n")
        prerequisites.chmod(0o700)
        jar = self.work / "suite/target/fapi-test-suite.jar"
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"fixture jar")
        run = self.bundle("tmp/custom output/run-one")
        supplemental = self.supplemental()
        env = os.environ.copy()
        for name in list(env):
            if name.startswith("CONFORMANCE_") or name in ("MAKEFLAGS", "MFLAGS"):
                env.pop(name)
        command = ["make", "--no-print-directory", "oidc-conformance-cleanup", "PYTHON=" + sys.executable]
        with artifacts.workspace_lock(self.root, "run"):
            blocked = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("active", blocked.stderr)
            self.assertTrue(run.exists())
            self.assertTrue(all(p.exists() for p in supplemental))
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(run.exists())
        self.assertTrue(all(not p.exists() for p in supplemental))
        self.assertEqual(jar.read_bytes(), b"fixture jar")
        self.assertEqual(subprocess.check_output([prerequisites]), b"retained-tool\n")
        with artifacts.workspace_lock(self.root, "run"):
            artifacts.mark_output(self.root, run, None)
        self.assertTrue((run / artifacts.MARKER).is_file())


if __name__ == "__main__":
    unittest.main()
