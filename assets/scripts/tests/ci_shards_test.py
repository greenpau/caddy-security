"""Exercise CI sharding, complete coverage, and failure gates through real workflows."""

import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
ROOT_SHARDS = ('root-core', 'root-clients', 'root-cli', 'root-direct-oauth',
               'root-oidc', 'root-refresh', 'root-browser', 'root-cross-device', 'root-runtime')
SHARDS = (*ROOT_SHARDS, 'packages')
MODULE = 'example.invalid/cishards'


class CIShardsUnitTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('ci_tests', ROOT / 'assets/scripts/ci_tests.py')
        self.ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ci)

    def test_partition_is_exhaustive_and_keeps_overlapping_journeys_together(self):
        expected = {
            'root-core': ['ExampleValue', 'FuzzFuture', 'TestFuture'],
            'root-clients': ['TestAuthenticationClient'],
            'root-cli': ['TestAuthenticator'],
            'root-direct-oauth': ['TestDirectOAuthRefresh'],
            'root-oidc': ['TestOIDC'],
            'root-refresh': ['TestOIDCRefreshBrowser'],
            'root-browser': ['TestBrowser'],
            'root-cross-device': ['TestCrossDeviceBrowser'],
            'root-runtime': ['TestAppFuture', 'TestCaddyFuture'],
        }
        names = sorted(itertools.chain.from_iterable(expected.values()))
        self.assertEqual(self.ci.root_partition(names), expected)
        for invalid in ([], names + [names[-1]], ['TestOnly'], ['invalid/name']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.ci.root_partition(invalid)

    def test_new_packages_are_discovered_once_and_root_is_the_only_overlap(self):
        graph = {MODULE: {'Dir': str(ROOT)},
                 MODULE + '/pkg/future': {'Dir': str(ROOT / 'pkg/future')}}
        plan = self.ci.partition(graph)
        self.assertEqual(plan, {**{shard: [MODULE] for shard in ROOT_SHARDS},
                                'packages': [MODULE + '/pkg/future']})
        for invalid in ({}, {MODULE: graph[MODULE]},
                        {MODULE: {'Dir': str(ROOT.parent)}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.ci.partition(invalid)


class CIShardsTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='caddy CI shards ', dir=ROOT / 'tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_', 'TEST_', 'TESTED_', 'CHANGE_', 'CI_'))
                    and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'COVERAGE_DIR', 'GOFLAGS',
                                    'GOWORK', 'MINIMUM_COVERAGE')}
        self.env.update(PYTHONDONTWRITEBYTECODE='1', GOWORK='off',
                        COVERAGE_DIR='reports with spaces', TEST='^MustNotExcludeTests$',
                        TEST_DIR='./missing', GIT_COMMIT='fixture', GIT_BRANCH='main')
        shutil.copyfile(ROOT / 'Makefile', self.root / 'Makefile')
        scripts = self.root / 'assets/scripts'
        scripts.mkdir(parents=True)
        for name in ('ci_tests.py', 'test_guard.py'):
            shutil.copyfile(ROOT / 'assets/scripts' / name, scripts / name)
        (self.root / 'VERSION').write_text('1.0.0\n')
        pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
        (self.root / 'go.mod').write_text('module ' + MODULE + '\n\ngo 1.26.0\n\n'
                                        f'require github.com/greenpau/tested {pinned}\n\n'
                                        'tool github.com/greenpau/tested\n')
        (self.root / 'go.sum').write_text(''.join(
            line for line in (ROOT / 'go.sum').read_text().splitlines(True)
            if line.startswith('github.com/greenpau/tested ')))

    def package(self, directory, tested=True):
        destination = self.root / directory
        destination.mkdir(parents=True, exist_ok=True)
        (destination / 'value.go').write_text('package fixture\nfunc Value() int { return 42 }\n')
        if tested:
            (destination / 'value_test.go').write_text(
                'package fixture\nimport ("os"; "testing")\n'
                'func TestE2EValue(t *testing.T) {\n'
                ' if Value() != 42 { t.Fatal("incorrect value") }\n'
                f' if os.Getenv("SHARD_FAIL") == "fail:{directory}" {{ t.Fatal("fixture failure") }}\n'
                '}\n')

    def command(self, *args, success=True, env=None, cwd=None):
        result = subprocess.run(args, cwd=cwd or self.root, env=env or self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def cli(self, *args, **kwargs):
        return self.command('python3', 'assets/scripts/ci_tests.py', *args, **kwargs)

    def test_e2e_complete_disjoint_shards_reports_and_failed_rerun(self):
        expected = {
            **{name: [''] for name in ROOT_SHARDS},
            'packages': ['cmd/server', 'pkg/future', 'pkg/enums'],
        }
        for directory in itertools.chain.from_iterable(expected.values()):
            self.package(directory, tested=directory != 'pkg/enums')
        root_source = self.root
        (root_source / 'value.go').write_text(
            'package fixture\n' + ''.join(
                f'func {name}() int {{ return 42 }}\n'
                for name in ('Value', 'Challenge', 'Session', 'Protocol', 'Unused')))
        (root_source / 'value_test.go').write_text('''package fixture
import ("fmt"; "os"; "testing")
func TestE2ECrossDevice(t *testing.T) {
 if Challenge() != 42 { t.Fatal("challenge") }
 t.Run("nested/Session", func(t *testing.T) { Challenge() })
}
func TestE2EDirectOAuth(t *testing.T) { Protocol() }
func TestE2EAuthenticationClient(t *testing.T) { Value() }
func TestE2EAuthenticator(t *testing.T) { Value() }
func TestE2EBrowser(t *testing.T) { Value() }
func TestAppRuntime(t *testing.T) { Value() }
func TestE2ERefreshValue(t *testing.T) { Session() }
func TestE2EOIDCValue(t *testing.T) { Protocol() }
func TestE2EValue(t *testing.T) {
 Value()
 if os.Getenv("SHARD_FAIL") == "fail:" { t.Fatal("fixture failure") }
}
func TestE2EValueLonger(t *testing.T) { Value() }
func TestE2EValueSession(t *testing.T) { Session() }
func TestE2ENewFeature(t *testing.T) { Value() }
func ExampleValue() { fmt.Println(Value()); // Output: 42
}
func FuzzSessionSeeds(f *testing.F) {
 f.Add("seed")
 f.Fuzz(func(t *testing.T, input string) { Session() })
}
''')
        # Executable Go discovery respects build constraints, external test packages,
        # runnable examples and fuzz targets, rather than matching source text.
        (root_source / 'ignored_test.go').write_text(
            '//go:build neverenabled\n\npackage fixture\n'
            'func TestInvalidSyntax(\n')
        (root_source / 'external_test.go').write_text(
            'package fixture_test\nimport "testing"\n'
            'func TestExternalNewFeature(t *testing.T) {}\n')
        source = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        plan = json.loads(self.cli('plan').stdout)
        expected = {shard: sorted(MODULE + ('/' + path if path else '') for path in paths)
                    for shard, paths in expected.items()}
        self.assertEqual(plan, expected)
        matrix = json.loads(self.cli('matrix').stdout)['include']
        self.assertEqual([row['shard'] for row in matrix], list(SHARDS))
        self.assertEqual([row['cache_group'] for row in matrix],
                         ['root'] * 9 + ['packages'])
        self.assertEqual([row['shard'] for row in matrix if row['browser']],
                         ['root-refresh', 'root-browser', 'root-cross-device'])
        base = self.root / 'reports with spaces'
        for shard in SHARDS:
            if shard == 'root-core':
                # Direct invocation from outside the checkout must place the plan
                # beside the reports produced by the nested Make invocation.
                self.command('python3', str(self.root / 'assets/scripts/ci_tests.py'),
                             'run', shard, cwd=self.root.parent,
                             env=dict(self.env, TEST_PACKAGE_PARALLELISM='2'))
            else:
                self.command('make', 'ci-test-shard', 'CI_SHARD=' + shard,
                             'TEST_PACKAGE_PARALLELISM=2')
            output = base / 'shards' / shard
            run = json.loads((output / 'run.json').read_text())
            command = run['command']
            self.assertIn('-race', command)
            self.assertIn('-count=1', command)
            self.assertEqual(command[command.index('-p') + 1], '2')
            pattern = command[command.index('-run') + 1]
            if shard in ROOT_SHARDS:
                self.assertTrue(pattern.startswith('^(') and pattern.endswith(')$'), pattern)
                selection = json.loads((output / 'selection.json').read_text())
                names = selection['selected_tests']
                self.assertTrue(names)
                self.assertEqual([n for n in selection['root_tests'] if re.search(pattern, n)],
                                 names)
                events = [json.loads(line) for line in
                          (output / 'test_output.jsonl').read_text().splitlines()]
                actual = [e['Test'] for e in events if e['Action'] == 'pass'
                          and e.get('Test') and '/' not in e['Test']]
                self.assertEqual(sorted(actual), names)
                discovery = json.loads((output / 'discovery/resource-usage.json').read_text())
                self.assertEqual(discovery['status'], 'passed')
            else:
                self.assertEqual(pattern, '.')
            self.assertEqual(command[-len(plan[shard]):], plan[shard])
            self.assertTrue((output / 'manifest.json').is_file())
            self.cli('summarize', shard)
            timing = json.loads((output / 'timing.json').read_text())
            self.assertEqual({p['package'] for p in timing['packages']}, set(plan[shard]))
            self.assertTrue(timing['slowest_tests'])
        self.cli('merge')
        combined = base / 'combined'
        summary = json.loads((combined / 'summary.json').read_text())
        self.assertEqual(summary['packages'], 4)
        self.assertEqual(summary['root_tests'], 15)
        self.assertEqual(summary['covered'], 6)
        self.assertEqual(summary['statements'], 8)
        self.assertAlmostEqual(summary['percent'], 100 * 6 / 8)
        # Compare a real unsplit run: overlapping root blocks must sum their
        # counters and count source statements once, preserving the coverage union.
        self.command('make', 'test', 'TEST=.', 'TEST_DIR=./...', 'COVERAGE_DIR=unsplit')
        def profile(path):
            return sorted(path.read_text().splitlines())
        self.assertEqual(profile(combined / 'coverage.out'),
                         profile(self.root / 'unsplit/coverage.out'))
        # The aggregate is a real Go coverage profile, usable by standard tooling.
        coverage = self.command('go', 'tool', 'cover', '-func', str(combined / 'coverage.out'))
        self.assertIn('75.0%', coverage.stdout)
        self.command('go', 'tool', 'cover', '-html', str(combined / 'coverage.out'),
                     '-o', str(combined / 'source.html'))
        for shard in SHARDS:
            self.assertIn(f'../shards/{shard}/index.html', (combined / 'index.html').read_text())
        for path, original in source.items():
            self.assertEqual(path.read_bytes(), original, str(path))

        # Reject incomplete/overlapping/failed evidence without replacing the last good aggregate.
        good_profile = (combined / 'coverage.out').read_bytes()
        root = base / 'shards/root-core'
        def reject(path, data, reason):
            original = path.read_bytes()
            manifest_path = path.parent / 'manifest.json'
            original_manifest = manifest_path.read_bytes()
            manifest = json.loads(original_manifest)
            path.write_bytes(data)
            # Re-seal synthetic evidence to exercise semantic checks independently
            # of the manifest hash check; separately test corrupted hashes below.
            for entry in manifest['files']:
                if entry['name'] == path.name:
                    entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            manifest_path.write_text(json.dumps(manifest))
            try:
                self.assertIn(reason, self.cli('merge', success=False).stdout)
                self.assertEqual((combined / 'coverage.out').read_bytes(), good_profile)
            finally:
                path.write_bytes(original)
                manifest_path.write_bytes(original_manifest)
        corruptions = [
            ('run.json', lambda data: dict(data, capture_complete=False)),
            ('run.json', lambda data: dict(data, exit_code=1)),
            ('resource-usage.json', lambda data: dict(data, status='aborted')),
            ('selection.json', lambda data: dict(data, packages=[])),
            ('selection.json', lambda data: dict(data, complete=False)),
            ('selection.json', lambda data: dict(data, selected_tests=[])),
            ('selection.json', lambda data: dict(data, all_shards={**data['all_shards'], 'packages': []})),
        ]
        for name, mutate in corruptions:
            with self.subTest(corruption=name):
                path = root / name
                original = path.read_bytes()
                path.write_text(json.dumps(mutate(json.loads(original))))
                self.cli('merge', success=False)
                path.write_bytes(original)
                self.assertEqual((combined / 'coverage.out').read_bytes(), good_profile)
        events_path = root / 'test_output.jsonl'
        original = events_path.read_bytes()
        events = [json.loads(line) for line in original.splitlines()]
        terminal = next(e for e in events if e['Action'] == 'pass' and not e.get('Test'))
        test = next(e for e in events if e['Action'] == 'pass' and e.get('Test')
                    and '/' not in e['Test'])
        for changed, reason in (
                ([e for e in events if e != terminal], 'Not every selected package'),
                (events + [terminal], 'Duplicate package execution'),
                (events + [dict(terminal, Action='fail')], 'Failed test evidence'),
                ([e for e in events if e != test], 'Not every selected root test'),
                (events + [test], 'Unexpected or duplicate root test'),
                (events + [dict(test, Test='TestE2ERefreshValue')],
                 'Not every selected root test')):
            reject(events_path, ''.join(json.dumps(e) + '\n' for e in changed).encode(), reason)
        profile = root / 'coverage.out'
        original = profile.read_bytes()
        lines = original.splitlines(keepends=True)
        reject(profile, original + lines[1], 'Invalid or overlapping coverage block')
        reject(profile, b''.join(lines[:-1]), 'different source blocks')
        block, statements, count = lines[1].decode().split()
        reject(profile, lines[0] + f'{block} {int(statements)+1} {count}\n'.encode()
               + b''.join(lines[2:]), 'Unexpected coverage overlap')
        for name in ('manifest.json', 'index.html'):
            path = root / name
            original = path.read_bytes()
            path.unlink()
            self.cli('merge', success=False)
            path.write_bytes(original)
        path = root / 'index.html'
        original = path.read_bytes()
        path.write_bytes(original + b'corrupted report')
        self.cli('merge', success=False)
        path.write_bytes(original)
        self.cli('merge')

        # A discovery failure on a previously successful shard cannot reuse its
        # old passed reports. Rebuild once repaired, then exercise test failure.
        source = self.root / 'value_test.go'
        original = source.read_bytes()
        source.write_text('package fixture\nfunc broken(\n')
        self.command('make', 'ci-test-shard', 'CI_SHARD=root-core', success=False)
        self.assertFalse(json.loads((root / 'selection.json').read_text())['complete'])
        self.cli('summarize', 'root-core')
        timing = json.loads((root / 'timing.json').read_text())
        self.assertIn('earlier attempt', timing['incomplete'])
        self.assertIn('Unfinished shard execution', self.cli('merge', success=False).stdout)
        source.write_bytes(original)
        self.command('make', 'ci-test-shard', 'CI_SHARD=root-core')
        self.cli('merge')

        other = {p: p.read_bytes() for p in (base / 'shards/packages').iterdir() if p.is_file()}
        env = dict(self.env, SHARD_FAIL='fail:')
        self.command('make', 'ci-test-shard', 'CI_SHARD=root-core', env=env, success=False)
        self.cli('summarize', 'root-core')
        timing = json.loads((root / 'timing.json').read_text())
        self.assertTrue(any(p['outcome'] == 'fail' for p in timing['packages']))
        self.cli('merge', success=False)
        self.command('make', 'run-reports', 'COVERAGE_DIR=' + str(root), success=False)
        for path, content in other.items():
            self.assertEqual(path.read_bytes(), content)
        # A compilation failure must also propagate through the public shard entry point.
        (self.root / 'value_test.go').write_text('package fixture\nfunc broken(\n')
        self.command('make', 'ci-test-shard', 'CI_SHARD=root-core', success=False)
        self.cli('merge', success=False)

    def test_gate_rejects_failure_skip_cancellation_and_missing_selection(self):
        outcomes = ('success', 'failure', 'cancelled', 'skipped', '')
        for selection, go_result, quality_result in itertools.product(outcomes, repeat=3):
            env = dict(self.env, SELECTION_RESULT=selection,
                       GO_RESULT=go_result, QUALITY_RESULT=quality_result)
            self.cli('gate', env=env,
                     success=(selection == go_result == quality_result == 'success'))

    def test_missing_graph_unknown_shard_and_incomplete_reports_fail(self):
        self.cli('plan', success=False)
        self.command('make', 'ci-test-shard', 'CI_SHARD=typo', success=False)
        self.cli('merge', success=False)
        self.assertFalse((self.root / 'reports with spaces/combined').exists())
        self.cli('summarize', 'root-core')
        timing = json.loads((self.root / 'reports with spaces/shards/root-core/timing.json').read_text())
        self.assertTrue(timing['incomplete'])
        self.assertEqual(timing['packages'], [])


if __name__ == '__main__':
    unittest.main()
