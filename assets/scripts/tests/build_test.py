"""Build metadata must remain data when a Git branch contains shell syntax."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class BuildMetadataTests(unittest.TestCase):
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
