"""Verify build outputs, failure propagation and safe treatment of metadata."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class BuildMetadataTests(unittest.TestCase):
    def test_make_build_builds_and_runs_both_commands_and_propagates_failures(self):
        with tempfile.TemporaryDirectory(prefix='caddy-security-build-') as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
            (root / 'VERSION').write_text('1.1.64\n')
            for source in ('assets/scripts/version.py', 'cmd/caddy-authenticator/main.go'):
                target = root / source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / source, target)
            # Keep the fixture independent of this checkout's current release.
            main = root / 'cmd/caddy-authenticator/main.go'
            main.write_text('app.SetVersion(appVersion, "1.1.64")\n')
            shims = root / 'shims'
            shims.mkdir()
            go = shims / 'go'
            go.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
args = sys.argv[1:]
with open('build-log', 'a') as log:
    log.write(json.dumps(args) + '\\n')
if args[-1] == os.environ.get('FAIL_PACKAGE'):
    sys.exit(1)
output = pathlib.Path(args[args.index('-o') + 1])
output.write_text('#!/bin/sh\\n[ "$1" = version ] || exit 1\\necho ' + output.name + '\\n')
output.chmod(0o755)
''')
            go.chmod(0o755)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
            env['PATH'] = str(shims) + os.pathsep + env['PATH']
            log = root / 'build-log'

            def make():
                return subprocess.run(['make', 'build'], cwd=root, env=env, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)

            result = make()
            self.assertEqual(result.returncode, 0, result.stdout)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([call[-1] for call in calls], ['./cmd/authcrunch', './cmd/caddy-authenticator'])
            for call, binary in zip(calls, ('authcrunch', 'caddy-authenticator')):
                self.assertIn('-mod=readonly', call)
                self.assertIn('-trimpath', call)
                self.assertEqual(call[call.index('-o') + 1], './bin/' + binary)
                self.assertIn(binary + '\n', result.stdout)
            self.assertEqual(calls[1][calls[1].index('-ldflags') + 1], '-X main.appVersion=1.1.64')
            for package, expected_calls in (('./cmd/authcrunch', 1), ('./cmd/caddy-authenticator', 2)):
                log.write_text('')
                env['FAIL_PACKAGE'] = package
                result = make()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('build: complete', result.stdout)
                self.assertEqual(len(log.read_text().splitlines()), expected_calls)
            env.pop('FAIL_PACKAGE')
            log.write_text('')
            (root / 'VERSION').write_text('1.1.65\n')
            result = make()
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('make version-sync', result.stdout)
            self.assertEqual(log.read_text(), '')

    def test_git_branch_cannot_execute_shell_commands(self):
        with tempfile.TemporaryDirectory(prefix='caddy-security-build-') as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
            (root / 'VERSION').write_text('1.1.41\n')
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith('GIT_') and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
            branch = 'build$(touch${IFS}unexpected)'
            subprocess.run(['git', 'init', '-q', '-b', branch], cwd=root, env=env, check=True)
            # An unborn branch still has its real name via symbolic-ref.
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'ops: fixture'],
                           cwd=root, env=env, check=True)
            result = subprocess.run(['make', 'info'], cwd=root, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(branch, result.stdout)
            self.assertFalse((root / 'unexpected').exists(), result.stdout)


if __name__ == '__main__':
    unittest.main()
