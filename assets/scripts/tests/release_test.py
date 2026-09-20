"""Exercise public release targets with real Git/versioned and local-only remotes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='release-', dir=ROOT / 'tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'work'
        self.remote = Path(self.temp.name) / 'origin.git'
        self.root.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_'))
                    and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Release Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_NAME='Release Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        PYTHONDONTWRITEBYTECODE='1')
        for name in ('assets/scripts/version.py', 'assets/scripts/release.sh',
                     'assets/scripts/generate_downloads.sh', 'go.mod', 'go.sum'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        self.main = self.root / 'cmd/caddy-authenticator/main.go'
        self.main.parent.mkdir(parents=True)
        self.main.write_text('package main\nfunc init() {\n'
                             '    app.SetVersion(appVersion, "1.1.64")\n}\n')
        (self.root / 'VERSION').write_text('1.1.64\n')
        (self.root / 'README.md').write_text(
            '# Fixture\n\nDownload Caddy with the plugins enabled:\n'
            '* <a href="https://caddyserver.com/api/download?old">old link</a>\n\nEnd.\n')
        (self.root / '.gitignore').write_text('.fixture/\n__pycache__/\n')
        (self.root / '.fixture').mkdir()
        # Public targets come from the actual Makefile. Recursive gates are bounded
        # fixtures so this tests orchestration without recursively running this suite.
        (self.root / 'Makefile').write_text(
            '.PHONY: version-check version-sync ci-check\n'
            'version-check:\n\t@python3 assets/scripts/version.py check\n'
            'version-sync:\n\t@python3 assets/scripts/version.py sync\n'
            'ci-check: version-check\n\t@python3 gate.py\n')
        (self.root / 'gate.py').write_text(
            'import os, subprocess\nfrom pathlib import Path\n'
            'with Path(".fixture/gates").open("a") as log:\n'
            '    log.write(Path("VERSION").read_text().strip()+"\\n")\n'
            'mode = os.environ.get("DIRTY_GATE")\n'
            'if mode == "untracked": Path("unexpected").write_text("change")\n'
            'if mode == "tracked": Path("gate.py").write_text("changed")\n'
            'if mode == "staged":\n'
            '    Path("unexpected").write_text("change")\n'
            '    subprocess.run(["git", "add", "unexpected"], check=True)\n'
            'if os.environ.get("FAIL_GATE") == "1": raise SystemExit(1)\n')
        self.run_command('git', 'init', '-q', '-b', 'main')
        self.run_command('git', 'add', '.')
        self.run_command('git', 'commit', '-qm', 'ops: fixture baseline')
        self.initial = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.run_command('git', 'init', '--bare', '-q', str(self.remote))
        self.run_command('git', 'remote', 'add', 'origin', str(self.remote))
        self.run_command('git', 'push', '-q', '-u', 'origin', 'main')

    def run_command(self, *args, ok=True, env=None):
        result = subprocess.run(args, cwd=self.root, env=env or self.env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=120)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        return result

    def release(self, kind='patch', ok=True, **variables):
        target = {'patch': 'release', 'minor': 'minor-release', 'check': 'release-git-check'}[kind]
        return self.run_command('make', '-j2', '-f', str(ROOT / 'Makefile'), target, ok=ok,
                                env=dict(self.env, **variables))

    def remote_head(self):
        return self.run_command('git', '--git-dir', str(self.remote), 'rev-parse', 'main').stdout.strip()

    def assert_published_release(self, version):
        tag = f'v{version}'
        self.assertEqual((self.root / 'VERSION').read_text().strip(), version)
        self.assertEqual((self.root / '.fixture/gates').read_text(), version + '\n')
        self.run_command('make', 'version-check')
        readme = (self.root / 'README.md').read_text()
        self.assertTrue(readme.startswith('# Fixture\n'))
        self.assertTrue(readme.endswith('\nEnd.\n'))
        self.assertEqual(readme.count('caddyserver.com/api/download'), 2)
        self.assertEqual(readme.count(f'caddy-security%40{tag}'), 2)
        self.assertNotIn('?old', readme)
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        head = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.assertEqual(self.remote_head(), head)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout.strip(), tag)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote),
                                          'cat-file', '-t', tag).stdout.strip(), 'tag')
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote),
                                          'rev-parse', f'{tag}^{{commit}}').stdout.strip(), head)
        self.assertEqual(self.run_command('git', 'show', '--format=%s', '--no-patch').stdout.strip(),
                         f'ops: released {tag}')
        self.assertEqual(self.run_command('git', 'diff-tree', '--no-commit-id', '--name-only',
                                          '-r', 'HEAD').stdout.splitlines(),
                         ['README.md', 'VERSION', 'cmd/caddy-authenticator/main.go'])

    def test_patch_release_publishes_only_exact_annotated_tag(self):
        self.run_command('git', 'tag', '-a', 'unrelated-local-tag', '-m', 'unrelated')
        self.run_command('git', 'config', 'push.followTags', 'true')
        self.release()
        self.assert_published_release('1.1.65')

    def test_minor_release_resets_patch(self):
        self.release('minor')
        self.assert_published_release('1.2.0')

    def test_release_check_does_not_bump_or_publish(self):
        self.release('check')
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)

    def test_dirty_staged_untracked_and_wrong_branch_are_rejected(self):
        for mode in ('untracked', 'staged', 'tracked', 'branch', 'detached'):
            with self.subTest(mode=mode):
                if mode in ('untracked', 'staged'):
                    (self.root / 'extra').write_text('dirty')
                    if mode == 'staged':
                        self.run_command('git', 'add', 'extra')
                elif mode == 'tracked':
                    (self.root / 'README.md').write_text('dirty')
                elif mode == 'branch':
                    self.run_command('git', 'checkout', '-qb', 'feature')
                else:
                    self.run_command('git', 'checkout', '--detach', '-q')
                self.assertNotEqual(self.release('minor', ok=False).returncode, 0)
                self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
                self.assertEqual(self.remote_head(), self.initial)
                self.assertFalse((self.root / '.fixture/gates').exists())
                # Cleanup is confined to this test's disposable repository.
                self.run_command('git', 'reset', '--hard', '-q', self.initial)
                (self.root / 'extra').unlink(missing_ok=True)
                self.run_command('git', 'checkout', '-q', 'main')

    def test_version_drift_fails_before_bump(self):
        (self.root / 'VERSION').write_text('1.1.63\n')
        self.run_command('git', 'add', 'VERSION')
        self.run_command('git', 'commit', '-qm', 'ops: fixture version drift')
        head = self.run_command('git', 'rev-parse', 'HEAD').stdout.strip()
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.63')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), head)
        self.assertEqual(self.remote_head(), self.initial)

    def test_gate_failure_keeps_changes_unpublished_and_retry_does_not_bump_again(self):
        self.assertNotEqual(self.release('minor', ok=False, FAIL_GATE='1').returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.2.0')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.2.0\n')
        self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(self.run_command('git', 'tag').stdout, '')
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout, '')
        self.assertEqual(self.run_command('git', 'diff', '--cached', '--name-only').stdout, '')
        self.assertEqual(self.run_command('git', 'diff', '--name-only').stdout.splitlines(),
                         ['README.md', 'VERSION', 'cmd/caddy-authenticator/main.go'])
        self.assertNotEqual(self.release('minor', ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.2.0')
        self.assertEqual((self.root / '.fixture/gates').read_text(), '1.2.0\n')

    def test_unexpected_gate_output_is_not_committed(self):
        for mode in ('untracked', 'tracked', 'staged'):
            with self.subTest(mode=mode):
                self.assertNotEqual(self.release(ok=False, DIRTY_GATE=mode).returncode, 0)
                self.assertEqual(self.run_command('git', 'rev-parse', 'HEAD').stdout.strip(), self.initial)
                self.assertEqual(self.remote_head(), self.initial)
                self.run_command('git', 'reset', '--hard', '-q', self.initial)
                (self.root / 'unexpected').unlink(missing_ok=True)

    def test_existing_local_or_remote_tag_fails_before_bump(self):
        self.run_command('git', 'tag', 'v1.2.0')
        self.assertNotEqual(self.release('minor', ok=False).returncode, 0)
        self.run_command('git', 'push', '-q', 'origin', 'v1.2.0')
        self.run_command('git', 'tag', '-d', 'v1.2.0')
        self.assertNotEqual(self.release('minor', ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), self.initial)

    def test_stale_main_is_rejected_before_bump(self):
        self.run_command('git', 'commit', '--allow-empty', '-qm', 'ops: advance remote')
        self.run_command('git', 'push', '-q')
        remote = self.remote_head()
        self.run_command('git', 'reset', '--hard', '-q', self.initial)
        self.assertNotEqual(self.release(ok=False).returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), remote)

    def test_atomic_push_cannot_publish_main_without_tag(self):
        hook = self.remote / 'hooks/update'
        hook.write_text('#!/bin/sh\ncase "$1" in refs/tags/*) exit 1 ;; esac\nexit 0\n')
        hook.chmod(0o755)
        self.assertNotEqual(self.release('minor', ok=False).returncode, 0)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(self.run_command('git', '--git-dir', str(self.remote), 'tag').stdout, '')
        self.assertEqual(self.run_command('git', 'tag').stdout.strip(), 'v1.2.0')

    def test_missing_download_marker_fails_before_bump(self):
        (self.root / 'README.md').write_text('# Fixture\n')
        self.run_command('git', 'add', 'README.md')
        self.run_command('git', 'commit', '-qm', 'ops: remove fixture marker')
        result = self.release(ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('download insertion marker is missing', result.stdout)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), self.initial)

    def test_invalid_arguments_and_partial_targets_cannot_publish(self):
        for args in (('major',), ('minor', '--skip-tests'), ('check', 'extra')):
            with self.subTest(args=args):
                result = self.run_command('bash', 'assets/scripts/release.sh', *args, ok=False)
                self.assertNotEqual(result.returncode, 0)
        for target in ('release-update-version', 'release-git-commit'):
            result = self.run_command('make', '-f', str(ROOT / 'Makefile'), target, ok=False)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_text().strip(), '1.1.64')
        self.assertEqual(self.run_command('git', 'status', '--porcelain').stdout, '')
        self.assertFalse((self.root / '.fixture/gates').exists())
        self.assertEqual(self.remote_head(), self.initial)


if __name__ == '__main__':
    unittest.main()
