"""Verify version validation and artifact identities through the public Make targets."""

import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'assets/scripts/version.py'
spec = importlib.util.spec_from_file_location('caddy_security_version', SCRIPT)
version = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version)


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caddy-security-version-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'VERSION').write_text('1.1.64\n')
        self.main = self.root / version.AUTHENTICATOR_MAIN
        self.main.parent.mkdir(parents=True)
        self.main.write_text('package main\n\nfunc init() {\n\tapp.SetVersion(appVersion, "1.1.64")\n}\n')

    def test_valid_version_and_exact_tag(self):
        for text in ('1.1.64', '1.1.64\n'):
            with self.subTest(text=text):
                (self.root / 'VERSION').write_text(text)
                self.assertEqual(version.check_version(self.root, 'v1.1.64'), '1.1.64')
        with self.assertRaises(ValueError):
            version.check_version(self.root, 'v1.1.65')

    def test_namespace_rejects_noncanonical_versions(self):
        for text in ('2.0.0', '0.1.0', '1.01.2', '1.1.02', 'v1.1.64',
                     '1.1.64-rc1', '1.1.64+build', '1.1.64\n\n', ' 1.1.64',
                     '1.1', '1.1.64\nother', '1.1.64\r\n', '',
                     '1.1.18446744073709551615'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                (self.root / 'VERSION').write_bytes(text.encode())
                version.read_version(self.root)

    def test_next_version_preserves_major_and_resets_patch_for_minor(self):
        for current, kind, expected in (('1.1.64', 'patch', '1.1.65'),
                                        ('1.1.64', 'minor', '1.2.0'),
                                        ('1.2.0', 'minor', '1.3.0'),
                                        ('1.0.0', 'patch', '1.0.1')):
            with self.subTest(current=current, kind=kind):
                self.assertEqual(version.next_version(current, kind), expected)
        for current, kind in (('2.1.0', 'minor'), ('1.01.0', 'patch'),
                              ('1.1.64', 'major'),
                              ('1.1.18446744073709551614', 'patch'),
                              ('1.18446744073709551614.0', 'minor')):
            with self.subTest(current=current, kind=kind), self.assertRaises(ValueError):
                version.next_version(current, kind)

    def test_sync_changes_only_fallback_and_check_is_read_only(self):
        before = self.main.read_text()
        (self.root / 'VERSION').write_text('1.2.0\n')
        with self.assertRaisesRegex(ValueError, 'make version-sync'):
            version.check_version(self.root)
        self.assertEqual(self.main.read_text(), before)
        self.assertEqual(version.sync_version(self.root), '1.2.0')
        self.assertEqual(self.main.read_text(), before.replace('1.1.64', '1.2.0'))
        self.assertEqual(version.check_version(self.root, 'v1.2.0'), '1.2.0')
        updated = self.main.stat().st_mtime_ns
        version.sync_version(self.root)
        self.assertEqual(self.main.stat().st_mtime_ns, updated)

    def test_sync_rejects_missing_duplicate_or_invalid_inputs_without_writing(self):
        baseline = self.main.read_text()
        for source in ('package main\n', baseline + baseline):
            self.main.write_text(source)
            with self.subTest(source=source), self.assertRaises(ValueError):
                version.sync_version(self.root)
            self.assertEqual(self.main.read_text(), source)
        self.main.write_text(baseline)
        (self.root / 'VERSION').write_text('2.0.0\n')
        with self.assertRaises(ValueError):
            version.sync_version(self.root)
        self.assertEqual(self.main.read_text(), baseline)

    def test_artifact_identity_binds_version_time_and_commit(self):
        sha = 'abcdef0123456789' * 2 + 'abcdef01'
        self.assertEqual(version.artifact_identity('1.1.64', sha, 'branch', 'main',
                         '20260914T130000Z'), 'v1.1.64_20260914T130000Z_abcdef012345')
        self.assertEqual(version.artifact_identity('1.1.64', sha, 'tag', 'v1.1.64'), 'v1.1.64')
        for values in (('1.1.64', sha, 'tag', 'v1.1.63'),
                       ('1.1.64', 'abc', 'branch', 'main'),
                       ('1.1.64', sha, 'other', 'main'),
                       ('2.1.64', sha, 'branch', 'main')):
            with self.subTest(values=values), self.assertRaises(ValueError):
                version.artifact_identity(*values)
        with self.assertRaises(ValueError):
            version.artifact_identity('1.1.64', sha, 'branch', 'main', 'bad\noutput=1')

    def test_make_artifact_publishes_only_validated_outputs_without_source_changes(self):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('GIT_', 'GITHUB_'))
               and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        shutil.copyfile(ROOT / 'Makefile', self.root / 'Makefile')
        scripts = self.root / 'assets/scripts'
        scripts.mkdir(parents=True)
        shutil.copyfile(SCRIPT, scripts / 'version.py')
        subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=self.root, env=env, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'ops: fixture'],
                       cwd=self.root, env=env, check=True)
        sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, env=env, text=True).strip()
        sources = {path.relative_to(self.root): path.read_bytes()
                   for path in (self.root / 'VERSION', self.root / 'Makefile', scripts / 'version.py', self.main)}
        output = self.root / 'github-output'
        env['GITHUB_OUTPUT'] = str(output)

        def make(target):
            return subprocess.run(['make', target], cwd=self.root, env=env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)

        self.assertEqual(make('version-check').returncode, 0)
        result = make('artifact-id')
        self.assertEqual(result.returncode, 0, result.stdout)
        artifact = result.stdout.strip()
        self.assertRegex(artifact, rf'^v1\.1\.64_\d{{8}}T\d{{6}}Z_{re.escape(sha[:12])}$')
        self.assertEqual(output.read_text(), f'version=1.1.64\nartifact_id={artifact}\n')

        # PR runs bind to GITHUB_SHA (the checked merge revision), not the head branch.
        ci_sha = '1234567890abcdef' * 2 + '12345678'
        env.update(GITHUB_SHA=ci_sha, GITHUB_REF_TYPE='branch', GITHUB_REF_NAME='123/merge')
        output.write_text('')
        result = make('artifact-id')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(result.stdout.strip().endswith(ci_sha[:12]), result.stdout)

        env.update(GITHUB_REF_TYPE='tag', GITHUB_REF_NAME='v1.1.64')
        output.write_text('')
        result = make('artifact-id')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(output.read_text(), 'version=1.1.64\nartifact_id=v1.1.64\n')
        for override in ({'GITHUB_REF_NAME': 'v1.1.63'}, {'GITHUB_SHA': 'bad\noutput=1'}):
            with self.subTest(override=override):
                baseline = env.copy()
                env.update(override)
                before = output.read_bytes()
                result = make('artifact-id')
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(output.read_bytes(), before)
                env.clear()
                env.update(baseline)
        for path, content in sources.items():
            self.assertEqual((self.root / path).read_bytes(), content, str(path))

        # The public sync target projects an explicit VERSION edit; check/artifact never do.
        env.pop('GITHUB_REF_TYPE', None)
        env.pop('GITHUB_REF_NAME', None)
        (self.root / 'VERSION').write_text('1.1.65\n')
        before = output.read_bytes()
        self.assertNotEqual(make('version-check').returncode, 0)
        self.assertNotEqual(make('artifact-id').returncode, 0)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(self.main.read_bytes(), sources[version.AUTHENTICATOR_MAIN])
        result = make('version-sync')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(version.check_version(self.root), '1.1.65')


if __name__ == '__main__':
    unittest.main()
