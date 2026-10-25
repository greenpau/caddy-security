"""Check test deadline arguments without compiling or waiting for Go tests."""

import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
(ROOT / 'tmp').mkdir(exist_ok=True)


def workflow_job_timeout(workflow, job):
    """Read a named job's budget without accepting another job or step's timeout."""
    match = re.search(rf'^  {re.escape(job)}:\n(?P<body>.*?)(?=^  \S|\Z)',
                      workflow, re.M | re.S)
    if match is None:
        raise ValueError(f'Missing workflow job: {job}')
    timeout = re.search(r'^    timeout-minutes: ([1-9]\d*)[ \t]*$', match['body'], re.M)
    if timeout is None:
        raise ValueError(f'Missing timeout for workflow job: {job}')
    return int(timeout[1])


class TestTimeoutTests(unittest.TestCase):
    def test_job_timeout_is_independent_of_job_order_and_step_timeouts(self):
        jobs = {
            'selection': '  selection:\n    timeout-minutes: 5\n',
            'quality': '  quality:\n    timeout-minutes: 45\n',
            'go': '  go:\n    steps:\n      - timeout-minutes: 1\n    timeout-minutes: 85\n',
            'core': '  core:\n    timeout-minutes: 10\n',
        }
        for order in itertools.permutations(jobs):
            with self.subTest(order=order):
                workflow = 'jobs:\n' + ''.join(jobs[name] for name in order)
                self.assertEqual(workflow_job_timeout(workflow, 'go'), 85)
        for workflow in ('jobs:\n' + jobs['quality'],
                         'jobs:\n  go:\n    steps:\n      - timeout-minutes: 85\n' + jobs['quality']):
            with self.subTest(workflow=workflow), self.assertRaises(ValueError):
                workflow_job_timeout(workflow, 'go')

    def test_default_and_override_precedence_for_all_test_targets(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tmp', prefix='_caddy-security-timeout-') as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
            (root / 'assets/scripts').mkdir(parents=True)
            shutil.copyfile(ROOT / 'assets/scripts/test_guard.py', root / 'assets/scripts/test_guard.py')
            (root / 'VERSION').write_text('1.0.0\n')
            capture = root / 'arguments.json'
            # Observe the real Make recipe at its tool boundary. The lifecycle
            # E2E fixture separately verifies pinned tested and Go enforcement.
            tool = root / 'go'
            tool.write_text(f'#!{sys.executable}\n'
                            'import json, os, sys\n'
                            'from pathlib import Path\n'
                            'Path(os.environ["TEST_ARGUMENTS"]).write_text(json.dumps(sys.argv[1:]))\n')
            tool.chmod(0o755)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('GIT_', 'TEST_')) and key not in
                   ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'TEST_TIMEOUT')}
            env.update(PATH=str(root) + os.pathsep + env['PATH'],
                       TEST_ARGUMENTS=str(capture), TEST='^TestSelected$',
                       TEST_DIR='./pkg/example', QUICK_TEST_DIR='./pkg/quick',
                       COVERAGE_DIR='reports with spaces', MINIMUM_COVERAGE='1')
            cases = (
                ('default', None, None, '60m'),
                ('environment', '7m', None, '7m'),
                ('command line', '7m', '90s', '90s'),
            )
            for target in ('test', 'run-tests', 'qtest', 'run-quick-tests'):
                for name, environment, argument, expected in cases:
                    with self.subTest(target=target, timeout=name):
                        case_env = env.copy()
                        if environment is not None:
                            case_env['TEST_TIMEOUT'] = environment
                        command = ['make', '--no-print-directory', target,
                                   'GIT_COMMIT=fixture', 'GIT_BRANCH=main']
                        if argument is not None:
                            command.append('TEST_TIMEOUT=' + argument)
                        capture.unlink(missing_ok=True)
                        result = subprocess.run(command, cwd=root, env=case_env, text=True,
                                                capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        arguments = json.loads(capture.read_text())
                        self.assertEqual(arguments[:3], ['tool', 'tested', 'run'])
                        go_arguments = arguments[arguments.index('--') + 1:]
                        quick = target in ('qtest', 'run-quick-tests')
                        self.assertEqual(go_arguments, [
                            '-mod=readonly', '-race', '-count=1', '-p', '1',
                            '-parallel', '2', '-timeout', expected,
                            '-v', '-run', '^TestSelected$',
                            './pkg/quick' if quick else './pkg/example',
                        ])
                        self.assertEqual(arguments[arguments.index('--output-dir') + 1],
                                         'reports with spaces/quick' if quick else 'reports with spaces')
                        if name == 'default':
                            output = root / arguments[arguments.index('--output-dir') + 1]
                            budget = json.loads((output / 'resource-usage.json').read_text())
                            package_seconds = int(expected.removesuffix('m')) * 60
                            # Compilation/reporting must fit outside the package
                            # deadline; CI also needs setup/build/upload time.
                            self.assertGreaterEqual(budget['timeout_seconds'], package_seconds + 600)
                            workflow = (ROOT / '.github/workflows/build.yml').read_text()
                            job_minutes = workflow_job_timeout(workflow, 'go')
                            self.assertGreaterEqual(job_minutes * 60, budget['timeout_seconds'] + 300)


if __name__ == '__main__':
    unittest.main()
