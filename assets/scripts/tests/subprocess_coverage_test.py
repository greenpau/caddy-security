"""Exercise native subprocess coverage through Go and the real Make/tested reports."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class SubprocessCoverageTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix='subprocess-coverage-', dir=ROOT / 'tmp')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_') and key not in (
                        'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'GOFLAGS', 'GOCOVERDIR',
                        'TEST_TIMEOUT', 'CADDY_COVERAGE_FIXTURE_PROCESS')}
        self.env.update(PYTHONDONTWRITEBYTECODE='1', TEST='.', TEST_DIR='./...',
                        QUICK_TEST_DIR='.', COVERAGE_DIR='.coverage', MINIMUM_COVERAGE='1')
        for name in ('Makefile', 'subprocess_coverage_test.go'):
            shutil.copyfile(ROOT / name, self.root / name)
        for path in (ROOT / 'testdata/subprocess_coverage').glob('*.go'):
            shutil.copyfile(path, self.root / path.name)
        (self.root / 'VERSION').write_text('1.0.0\n')
        pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
        (self.root / 'go.mod').write_text('module example.invalid/coveragefixture\n\ngo 1.25.0\n\n'
                                         f'require github.com/greenpau/tested {pinned}\n\n'
                                         'tool github.com/greenpau/tested\n')
        (self.root / 'go.sum').write_text(''.join(
            line for line in (ROOT / 'go.sum').read_text().splitlines(True)
            if line.startswith('github.com/greenpau/tested ')))
        self.run_command('git', 'init', '-q', '-b', 'main')

    def run_command(self, *command, status=0, env=None):
        result = subprocess.run(command, cwd=self.root, env=env or self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        self.assertEqual(result.returncode, status, result.stdout)
        return result

    def assert_profile(self, path, expected, mode='atomic'):
        lines = path.read_text().splitlines()
        self.assertEqual(lines[0], f'mode: {mode}')
        counters = {}
        for line in lines[1:]:
            location, statements, count = line.split()
            self.assertIn('/fixture.go:', location)
            self.assertEqual(int(statements), 1)
            line_number = int(location.rsplit(':', 1)[1].split('.', 1)[0])
            self.assertNotIn(line_number, counters, 'duplicate coverage block')
            counters[line_number] = int(count)
        functions = {}
        for number, line in enumerate((self.root / 'fixture.go').read_text().splitlines(), 1):
            match = re.match(r'func (\w+)\(', line)
            if match:
                functions[match.group(1)] = counters.pop(number)
        self.assertEqual(counters, {})
        self.assertEqual(functions, expected)

    def expected_counters(self, **values):
        expected = dict(parentOnly=0, childOnly=0, grandchildOnly=0, exitOnly=0,
                        exitFailureOnly=0, failedChildOnly=0, untouched=0)
        expected.update(values)
        return expected

    def test_make_reports_merge_descendants_preserve_failures_and_start_fresh(self):
        report = self.root / 'reports with spaces'
        arguments = ('COVERAGE_DIR=reports with spaces',)
        self.run_command('make', 'test', 'TEST=^TestCoverage(E2E|Process)$', *arguments)
        expected = self.expected_counters(parentOnly=1, childOnly=2, grandchildOnly=2,
                                          exitOnly=1, exitFailureOnly=1)
        self.assert_profile(report / 'coverage.out', expected)
        summary = json.loads((report / 'summary.json').read_text())
        self.assertEqual(summary['outcome'], 'passed')
        self.assertEqual(summary['coverage']['covered'], 5)
        self.assertEqual(summary['coverage']['statements'], 7)
        self.assertEqual(summary['counts']['tests'].get('skipped'), 1)
        for name in ('index.html', 'coverage.html', 'junit.xml', 'manifest.json'):
            self.assertTrue((report / name).is_file(), name)
        before = (report / 'coverage.out').read_bytes()
        self.run_command('make', 'run-reports', *arguments)
        self.assertEqual((report / 'coverage.out').read_bytes(), before)

        # Coverage remains below 100%; untouched branches cannot disappear.
        self.run_command('make', 'test', 'TEST=^TestCoverageE2E$', 'MINIMUM_COVERAGE=100',
                         *arguments, status=2)
        self.assertNotEqual(json.loads((report / 'summary.json').read_text())['outcome'], 'passed')
        self.assert_profile(report / 'coverage.out', expected)

        self.run_command('make', 'test', 'TEST=^TestCoverageFailureE2E$', *arguments, status=2)
        self.assertEqual(json.loads((report / 'run.json').read_text())['exit_code'], 1)
        self.assertNotEqual(json.loads((report / 'summary.json').read_text())['outcome'], 'passed')
        self.assertIn('intentional child failure', (report / 'test_output.jsonl').read_text())
        self.assert_profile(report / 'coverage.out', self.expected_counters(failedChildOnly=1))
        self.run_command('make', 'run-reports', *arguments, status=2)

        # Reusing a destination and running a filtered/quick test cannot reuse old counters.
        self.run_command('make', 'test', 'TEST=^TestCoverageParentOnly$', *arguments)
        parent = self.expected_counters(parentOnly=1)
        self.assert_profile(report / 'coverage.out', parent)
        self.run_command('make', 'qtest', 'TEST=^TestCoverageE2E$', *arguments)
        self.assert_profile(report / 'quick/coverage.out', expected)
        self.assert_profile(report / 'coverage.out', parent)

    def test_plain_go_test_set_count_and_uninstrumented(self):
        for mode in ('set', 'count'):
            with self.subTest(mode=mode):
                profile = self.root / f'{mode}.out'
                self.run_command('go', 'test', '-mod=readonly', '-count=1',
                                 f'-covermode={mode}', f'-coverprofile={profile}',
                                 '-run=^TestCoverageE2E$', '.')
                self.assert_profile(profile, self.expected_counters(
                    parentOnly=1, childOnly=1 if mode == 'set' else 2,
                    grandchildOnly=1 if mode == 'set' else 2, exitOnly=1, exitFailureOnly=1), mode)
        # An unrelated environment variable must not activate coverage in a plain binary.
        unused = self.root / 'must not be created'
        result = self.run_command('go', 'test', '-mod=readonly', '-count=1',
                                  '-run=^TestCoverageE2E$', '.',
                                  env=dict(self.env, GOCOVERDIR=str(unused)))
        self.assertNotIn('coverage:', result.stdout)
        self.assertFalse(unused.exists())

    def test_unwritable_destination_fails_coverage_collection(self):
        binary = self.root / 'coverage-fixture.test'
        self.run_command('go', 'test', '-mod=readonly', '-c', '-covermode=atomic',
                         '-cover', '-o', str(binary), '.')
        # A regular file is never a valid coverage directory, even when tests
        # run with elevated filesystem permissions.
        destination = self.root / 'not a directory'
        destination.write_text('preserve this file\n')
        result = self.run_command(str(binary), '-test.run=^TestCoverageE2E$',
                                  f'-test.gocoverdir={destination}', status=2)
        self.assertIn('collect subprocess coverage:', result.stdout)
        self.assertEqual(destination.read_text(), 'preserve this file\n')


if __name__ == '__main__':
    unittest.main()
