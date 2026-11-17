"""Exercise interpreter selection through Make, unittest and a nested Make call."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class PythonSelectionTests(unittest.TestCase):
    def test_e2e_default_fallback_and_explicit_overrides(self):
        for modern, environment, argument, expected in [
            (True, None, None, 'python3.14'),
            (False, None, None, 'python3'),
            (True, 'python-selected', None, 'python-selected'),
            (True, 'python3', 'python-selected', 'python-selected'),
        ]:
            with self.subTest(modern=modern, environment=environment, argument=argument):
                with tempfile.TemporaryDirectory(prefix='python selection ') as temporary:
                    root = Path(temporary)
                    binaries = root / 'bin'
                    binaries.mkdir()
                    # Isolate discovery from the host's installed Python versions.
                    for command in ('make', 'head', 'git', 'whoami', 'date'):
                        binaries.joinpath(command).symlink_to(shutil.which(command))
                    names = ['python3', 'python-selected'] + (['python3.14'] if modern else [])
                    for name in names:
                        executable = binaries / name
                        executable.write_text(
                            f'#!{sys.executable}\nimport json, os, sys\n'
                            'from pathlib import Path\n'
                            'with Path("interpreters.jsonl").open("a") as stream:\n'
                            f'    stream.write(json.dumps({name!r}) + "\\n")\n'
                            f'os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n')
                        executable.chmod(0o755)
                    shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
                    (root / 'VERSION').write_text('1.0.0\n')
                    scripts = root / 'assets/scripts'
                    (scripts / 'tests').mkdir(parents=True)
                    (scripts / 'version.py').write_text(
                        'import json, os, sys\nfrom pathlib import Path\n'
                        'Path("nested.json").write_text(json.dumps({"python": os.environ.get("PYTHON"),'
                        '"executable": sys.executable}))\n')
                    (scripts / 'tests/probe_test.py').write_text(
                        'import os, subprocess, unittest\n'
                        'class Probe(unittest.TestCase):\n'
                        '    def test_selected_interpreter_is_exported(self):\n'
                        f'        self.assertEqual(os.environ.get("PYTHON"), {expected!r})\n'
                        '        subprocess.run(["make", "--no-print-directory", "version-check"], check=True)\n')
                    env = {key: value for key, value in os.environ.items()
                           if key not in ('PYTHON', 'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES')}
                    env['PATH'] = str(binaries)
                    if environment is not None:
                        env['PYTHON'] = environment
                    command = ['make', '--no-print-directory', 'GIT_COMMIT=fixture', 'GIT_BRANCH=main',
                               'test-automation']
                    if argument is not None:
                        command.append('PYTHON=' + argument)
                    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    observed = [json.loads(line) for line in (root / 'interpreters.jsonl').read_text().splitlines()]
                    self.assertEqual(observed, [expected, expected])
                    self.assertEqual(json.loads((root / 'nested.json').read_text()),
                                     {'python': expected, 'executable': sys.executable})
