"""Preparation guidance, blocked-run recovery, and evidence-safe removal."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'assets/scripts'))
import oidc_conformance as harness
import prepare_oidc_conformance as preparation


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='oidc-conformance-setup-', dir=ROOT / 'tmp')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_each_missing_downloaded_prerequisite_explains_recovery_in_console_and_html(self):
        suite = self.root / 'suite'
        suite.mkdir()
        executable = self.root / 'tool'
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o700)
        for missing in ('suite', 'java', 'mongod', 'runner_python', 'chrome', 'chromedriver', 'jar'):
            with self.subTest(missing=missing):
                args = SimpleNamespace(results=self.root / ('run-'+missing), local_only=False, suite=suite,
                                       java=executable, mongod=executable, runner_python=executable, chrome=executable, chromedriver=executable)
                if missing != 'jar':
                    setattr(args, missing, self.root / ('missing-'+missing))
                console = io.StringIO()
                # Stub the unit subprocess and git revision check. Exercise the
                # real missing-file checks, run lifecycle and HTML generation.
                with mock.patch.object(harness, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
                     mock.patch.object(harness, 'suite_check', side_effect=lambda p: p), \
                     redirect_stdout(console), redirect_stderr(console):
                    result = harness.run(args)
                self.assertEqual(result, 2)
                status = json.loads((args.results / 'execution.json').read_text())
                self.assertEqual(status['state'], 'BLOCKED')
                self.assertIsNone(status['runner_exit_code'])
                self.assertEqual(status['next_steps'], ['make oidc-conformance-prepare', 'make oidc-conformance-test'])
                for message in (console.getvalue(), (args.results / 'index.html').read_text()):
                    self.assertIn('make oidc-conformance-prepare', message)
                    self.assertIn('make oidc-conformance-help', message)
                    self.assertIn('new CONFORMANCE_RESULTS', message)

    def test_help_is_read_only_and_lists_local_install_locations(self):
        console = io.StringIO()
        with mock.patch.object(preparation, 'install') as install, \
             mock.patch.object(preparation, 'command') as command, \
             mock.patch.object(preparation, 'WORK', self.root / 'absent'), redirect_stdout(console):
            with self.assertRaises(SystemExit) as exit:
                preparation.main(['--help'])
        self.assertEqual(exit.exception.code, 0)
        install.assert_not_called()
        command.assert_not_called()
        self.assertFalse((self.root / 'absent').exists())
        for tool in ('tools/java', 'tools/mongodb', 'tools/maven', 'tools/chrome', 'tools/chromedriver'):
            self.assertIn(tool, console.getvalue())

    def test_documented_removal_preserves_run_bundles_and_custom_results(self):
        help_text = preparation.installation_help()
        command = help_text[help_text.index('  rm -rf '):].split('\n\n', 1)[0].replace('\\\n', '')
        args = shlex.split(command)
        self.assertEqual(args[:2], ['rm', '-rf'])
        for name in args[2:]:
            self.assertTrue(name.startswith('tmp/oidc-conformance/'))
            self.assertNotIn('..', Path(name).parts)
            path = self.root / name
            path.mkdir(parents=True)
            (path / 'downloaded-data').write_bytes(b'test fixture')
        retained = ['tmp/oidc-conformance/run-example/index.html',
                    'tmp/oidc-conformance/prerequisites.json', 'tmp/oidc-conformance/suite-build.log',
                    'tmp/custom-results/index.html']
        for name in retained:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'preserve evidence')
        subprocess.run(args, cwd=self.root, check=True, timeout=10)
        for name in args[2:]:
            self.assertFalse((self.root / name).exists())
        for name in retained:
            self.assertEqual((self.root / name).read_bytes(), b'preserve evidence')


if __name__ == '__main__':
    unittest.main()
