"""Exercise the release workflow's tag gate with real Git and a local bare remote."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
TAG = 'v1.2.0'
TAG_REF = f'refs/tags/{TAG}'


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='release-workflow-', dir=ROOT / 'tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'work'
        self.remote = Path(self.temp.name) / 'origin.git'
        self.root.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_'))}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Release Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='Release Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        PYTHONDONTWRITEBYTECODE='1', GITHUB_REF_TYPE='tag', GITHUB_REF_NAME=TAG)
        scripts = self.root / 'assets/scripts'
        scripts.mkdir(parents=True)
        shutil.copyfile(ROOT / 'assets/scripts/version.py', scripts / 'version.py')
        main = self.root / 'cmd/caddy-authenticator/main.go'
        main.parent.mkdir(parents=True)
        main.write_text('package main\nfunc init() {\n'
                        '    app.SetVersion(appVersion, "1.2.0")\n}\n')
        (self.root / 'VERSION').write_text('1.2.0\n')
        self.run_command('git', 'init', '-q', '-b', 'main')
        self.run_command('git', 'add', '.')
        self.run_command('git', 'commit', '-qm', 'ops: fixture release')
        self.sha = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.env['GITHUB_SHA'] = self.sha
        self.run_command('git', 'tag', '-a', TAG, '-m', TAG)
        self.tag_object = self.run_command('git', 'rev-parse', TAG_REF).stdout.strip()
        self.run_command('git', 'init', '--bare', '-q', str(self.remote))
        self.run_command('git', 'remote', 'add', 'origin', str(self.remote))
        self.run_command('git', 'push', '-q', 'origin', 'main', TAG_REF)
        self.run_command('git', 'checkout', '--detach', '-q', self.sha)

        # Execute the checked-in workflow block, so the fixture verifies the CI gate itself.
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        step = workflow.split('      - name: Verify release version and annotated tag\n', 1)[1]
        step = step.split('      - name:', 1)[0]
        self.gate = textwrap.dedent(step.split('        run: |\n', 1)[1])

    def run_command(self, *args, ok=True, env=None):
        result = subprocess.run(args, cwd=self.root, env=env or self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        return result

    def verify(self, ok=True, **variables):
        return self.run_command('bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c',
                                self.gate, ok=ok, env=dict(self.env, **variables))

    def test_restores_annotation_after_checkout_fetches_commit_into_tag_ref(self):
        # Reproduce actions/checkout's second fetch from the failed release job.
        self.run_command('git', 'fetch', '--no-tags', 'origin', f'+{self.sha}:{TAG_REF}')
        self.assertEqual(self.run_command('git', 'cat-file', '-t', TAG_REF).stdout.strip(), 'commit')
        self.verify()
        self.assertEqual(self.run_command('git', 'cat-file', '-t', TAG_REF).stdout.strip(), 'tag')
        self.assertEqual(self.run_command('git', 'rev-parse', TAG_REF).stdout.strip(), self.tag_object)
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.sha)
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote),
                                          'rev-parse', TAG_REF).stdout.strip(), self.tag_object)

    def test_accepts_existing_annotated_tag(self):
        self.verify()

    def test_rejects_lightweight_remote_tag_even_with_local_annotation(self):
        self.run_command('git', '--git-dir', str(self.remote), 'update-ref', TAG_REF, self.sha)
        result = self.verify(ok=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('must be an annotated tag', result.stdout)

    def test_rejects_missing_remote_tag_even_with_local_annotation(self):
        self.run_command('git', '--git-dir', str(self.remote), 'update-ref', '-d', TAG_REF)
        result = self.verify(ok=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_rejects_remote_tag_moved_to_another_commit(self):
        self.run_command('git', 'commit', '--allow-empty', '-qm', 'ops: another fixture commit')
        self.run_command('git', 'tag', '-af', TAG, '-m', 'moved fixture tag')
        self.run_command('git', 'push', '-q', '--force', 'origin', TAG_REF)
        self.run_command('git', 'checkout', '--detach', '-q', self.sha)
        self.run_command('git', 'update-ref', TAG_REF, self.tag_object)
        result = self.verify(ok=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('must point to the validated commit', result.stdout)

    def test_rejects_checkout_that_differs_from_event_commit(self):
        self.run_command('git', 'commit', '--allow-empty', '-qm', 'ops: another fixture commit')
        result = self.verify(ok=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('must point to the validated commit', result.stdout)

    def test_rejects_branch_dispatch_and_mismatched_tag_or_event_commit(self):
        for variables in ({'GITHUB_REF_TYPE': 'branch'}, {'GITHUB_REF_NAME': 'v1.2.1'},
                          {'GITHUB_SHA': '0' * 40}):
            with self.subTest(variables=variables):
                result = self.verify(ok=False, **variables)
                self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == '__main__':
    unittest.main()
