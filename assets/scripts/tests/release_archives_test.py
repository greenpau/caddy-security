"""Archive validation must reject incomplete, mixed or corrupted CLI releases."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'assets/scripts/check_authenticator_archives.py'
spec = importlib.util.spec_from_file_location('authenticator_archives', SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caddy-authenticator-archives-')
        self.addCleanup(self.temp.cleanup)
        self.dist = Path(self.temp.name)
        self.version = '1.2.3-SNAPSHOT-abc1234'
        (self.dist / 'metadata.json').write_text(json.dumps({'version': self.version}))
        self.files = {'LICENSE': (ROOT / 'LICENSE').read_bytes(),
                      'README.md': (ROOT / 'cmd/caddy-authenticator/README.md').read_bytes()}
        for system in ('linux', 'darwin', 'windows'):
            for arch in ('amd64', 'arm64'):
                self.write_archive(system, arch)
        self.checksums()

    def write_archive(self, system='linux', arch='amd64', extra=None, mode=0o755):
        files = dict(self.files)
        files['caddy-authenticator.exe' if system == 'windows' else 'caddy-authenticator'] = b'fixture executable'
        files.update(extra or {})
        extension = 'zip' if system == 'windows' else 'tar.gz'
        path = self.dist / f'caddy-authenticator_{self.version}_{system}_{arch}.{extension}'
        if system == 'windows':
            with zipfile.ZipFile(path, 'w') as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
        else:
            with tarfile.open(path, 'w:gz') as archive:
                for name, data in files.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = mode if name == 'caddy-authenticator' else 0o644
                    archive.addfile(entry, io.BytesIO(data))
        return path

    def checksums(self):
        output = ''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'
                         for path in sorted(self.dist.glob('caddy-authenticator_*')))
        (self.dist / f'authcrunch_{self.version}_SHA256SUMS').write_text(output)

    def test_complete_release_and_cli_exit_status(self):
        self.assertEqual(len(checker.check_archives(self.dist)), 6)
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.dist)], text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('6 standalone archives', result.stdout)
        next(self.dist.glob('*.zip')).unlink()
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.dist)], text=True,
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('matrix mismatch', result.stderr)

    def test_corruption_is_detected_before_opening_archive(self):
        path = next(self.dist.glob('*.zip'))
        path.write_bytes(b'corrupted archive')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            checker.check_archives(self.dist)

    def test_contents_permissions_and_guide(self):
        for system in ('linux', 'windows'):
            for extra, message in (({'authcrunch': b'wrong tool'}, 'unexpected archive contents'),
                                   ({'README.md': b'wrong guide'}, 'incorrect usage guide'),
                                   ({'caddy-authenticator.exe' if system == 'windows' else 'caddy-authenticator': b''}, 'empty binary')):
                with self.subTest(system=system, message=message):
                    self.write_archive(system, extra=extra)
                    self.checksums()
                    with self.assertRaisesRegex(ValueError, message):
                        checker.check_archives(self.dist)
                    self.write_archive(system)
                    self.checksums()
        for mode in (0o644, 0o654):
            with self.subTest(mode=oct(mode)):
                self.write_archive(mode=mode)
                self.checksums()
                with self.assertRaisesRegex(ValueError, 'not executable'):
                    checker.check_archives(self.dist)


if __name__ == '__main__':
    unittest.main()
