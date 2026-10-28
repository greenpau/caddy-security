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
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[3]
RUNTIME_SHARDS = tuple(f'root-runtime-{number:02d}' for number in range(1, 25))
ROOT_SHARDS = ('root-direct-oauth-expiry', 'root-cross-device-expiry',
               'root-core', 'root-browser', 'root-clients-legacy', 'root-clients-native',
               'root-cli-authenticator', 'root-cli-identity', 'root-cli-commands',
               'root-direct-oauth', 'root-oidc', 'root-oidc-rp', 'root-jwks',
               'root-access-signers', 'root-access-signers-persistence',
               'root-refresh', 'root-refresh-sqlite', 'root-refresh-browser',
               'root-cross-device', *RUNTIME_SHARDS)
SHARDS = (*ROOT_SHARDS, 'packages')
MODULE = 'example.invalid/cishards'


class CIShardsUnitTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tmp').mkdir(exist_ok=True)
        spec = importlib.util.spec_from_file_location('ci_tests', ROOT / 'assets/scripts/ci_tests.py')
        self.ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ci)

    def test_partition_is_exhaustive_and_keeps_overlapping_journeys_together(self):
        expected = {
            'root-core': ['ExampleValue', 'FuzzFuture', 'TestFuture'],
            'root-browser': ['TestBrowser'],
            'root-clients-legacy': ['TestAuthenticationClient'],
            'root-clients-native': ['TestAuthenticationClientNative'],
            'root-cli-authenticator': ['TestCaddyAuthenticatorE2E'],
            'root-cli-identity': ['TestCaddySQLiteIdentityCommandsE2E'],
            'root-cli-commands': ['TestSecurityCredential'],
            'root-direct-oauth': ['TestDirectOAuthRefresh'],
            'root-direct-oauth-expiry': ['TestCaddyDirectOAuthExpirationE2E'],
            'root-oidc': ['TestOIDC'],
            'root-oidc-rp': ['TestCaddyOIDCRelyingPartyE2E'],
            'root-jwks': ['TestJWKS'],
            'root-access-signers': ['TestAccessSigner'],
            'root-access-signers-persistence': ['TestCaddyAccessSignerPersistenceE2E'],
            'root-refresh': ['TestRefresh'],
            'root-refresh-sqlite': ['TestSQLiteRefresh'],
            'root-refresh-browser': ['TestOIDCRefreshBrowser'],
            'root-cross-device': ['TestCrossDeviceBrowser'],
            'root-cross-device-expiry': ['TestCaddyCrossDeviceExpirationE2E'],
        }
        runtime = [f'TestAppFuture{number:02d}' for number in range(48)]
        names = sorted([*itertools.chain.from_iterable(expected.values()), *runtime])
        groups = self.ci.root_partition(names)
        self.assertEqual({key: groups[key] for key in expected}, expected)
        selected = list(itertools.chain.from_iterable(groups[key] for key in RUNTIME_SHARDS))
        self.assertEqual(sorted(selected), runtime)
        self.assertEqual(len(selected), len(set(selected)))
        self.assertTrue(all(len(groups[key]) == 2 for key in RUNTIME_SHARDS))
        self.assertEqual(groups, self.ci.root_partition(names))
        # Preserve isolated long journeys as new runtime parents are added.
        long = ['TestCaddySecurityLocalE2E']
        extra = [f'TestCaddyFuture{number:02d}E2E' for number in range(32)]
        balanced = self.ci.root_partition(sorted([*names, *long, *extra]))
        for name in long:
            group = next(values for values in balanced.values() if name in values)
            self.assertEqual([test for test in group if test.endswith('E2E')], [name])
        browser_callers = self.ci.BROWSER_TESTS | {'TestCaddyCompositionE2E'}
        browser_names = sorted(set(names) | browser_callers)
        browser_groups = self.ci.root_partition(browser_names)
        flags = {row['shard']: row['browser'] for row in self.ci.matrix(browser_names)['include']}
        for name in browser_callers:
            shard = next(key for key, values in browser_groups.items() if name in values)
            self.assertTrue(flags[shard], name)
        self.assertFalse(flags['root-direct-oauth-expiry'])
        self.assertFalse(flags['root-cross-device-expiry'])
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

    def test_report_coalesces_root_lifecycle_and_preserves_test_events(self):
        self.ci.SHARDS = ('later', 'earlier', 'packages')
        with tempfile.TemporaryDirectory(dir=ROOT / 'tmp') as temporary:
            base = Path(temporary)
            original = []
            for shard, package, hour, elapsed in (
                    ('later', MODULE, 2, 3), ('earlier', MODULE, 1, 5),
                    ('packages', MODULE + '/other', 1, 2)):
                events = [dict(Action='start', Package=package, Time=f'2026-10-25T0{hour}:00:00Z'),
                          dict(Action='run', Package=package, Test='Test' + shard),
                          dict(Action='skip', Package=package, Test='Test' + shard),
                          dict(Action='pass', Package=package, Elapsed=elapsed,
                               Time=f'2026-10-25T0{hour}:01:00Z')]
                original.extend(events)
                output = base / 'shards' / shard / 'test_output.jsonl'
                output.parent.mkdir(parents=True)
                output.write_text(''.join(json.dumps(event) + '\n' for event in events))
            projected = list(self.ci.report_events(base, MODULE))
            root = [event for event in projected if event['Package'] == MODULE and not event.get('Test')]
            self.assertEqual([event['Action'] for event in root], ['start', 'pass'])
            self.assertEqual(root[0]['Time'], '2026-10-25T01:00:00Z')
            self.assertEqual(root[1]['Time'], '2026-10-25T02:01:00Z')
            self.assertEqual(root[1]['Elapsed'], 8)
            self.assertEqual([event for event in projected if event.get('Test')],
                             [event for event in original if event.get('Test')])
            self.assertEqual([event for event in projected if event['Package'] != MODULE],
                             [event for event in original if event['Package'] != MODULE])

    def test_package_timings_distinguish_parallel_span_and_cumulative_work(self):
        self.ci.SHARDS = ('first', 'second', 'packages')
        with tempfile.TemporaryDirectory(dir=ROOT / 'tmp') as temporary:
            base = Path(temporary)
            for shard, package, start, finish, elapsed in (
                    ('first', MODULE, '00:00:00+00:00', '00:00:05+00:00', 3),
                    ('second', MODULE, '00:00:01+00:00', '00:00:04+00:00', 4),
                    ('packages', MODULE + '/other', '01:00:00+01:00', '01:00:09+01:00', 6)):
                output = base / 'shards' / shard
                output.mkdir(parents=True)
                (output / 'run.json').write_text(json.dumps(dict(
                    started_at='2026-10-25T' + start, finished_at='2026-10-25T' + finish)))
                (output / 'test_output.jsonl').write_text(json.dumps(dict(
                    Action='pass', Package=package, Elapsed=elapsed)) + '\n')
            timing = self.ci.package_timings(base, MODULE)
            self.assertEqual(timing['wall_seconds'], 9)
            self.assertEqual(timing['package_seconds'], 13)
            self.assertEqual([(item['directory'], item['seconds']) for item in timing['packages']],
                             [('.', 7), ('other', 6)])
            execution = base / 'shards/first/run.json'
            execution.write_text(json.dumps(dict(started_at='2026-10-25T00:00:10Z',
                                                 finished_at='2026-10-25T00:00:05Z')))
            with self.assertRaises(ValueError):
                self.ci.package_timings(base, MODULE)

    def test_successful_shard_keeps_timings_without_publishing_job_summary(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tmp') as temporary:
            base = Path(temporary)
            summary = base / 'job-summary.md'
            with mock.patch.object(self.ci, 'ROOT', base), mock.patch.dict(os.environ, dict(
                    COVERAGE_DIR='reports', GITHUB_STEP_SUMMARY=str(summary))):
                output = self.ci.directory('root-core')
                output.mkdir(parents=True)
                (output / 'resource-usage.json').write_text(json.dumps(dict(status='passed')))
                (output / 'selection.json').write_text(json.dumps(dict(complete=True)))
                events = output / 'test_output.jsonl'
                events.write_text(json.dumps(dict(Action='pass', Package=MODULE, Elapsed=2)) + '\n')
                self.ci.summarize('root-core')
                self.assertFalse(summary.exists())
                self.assertEqual(json.loads((output / 'timing.json').read_text())['packages'][0]['seconds'], 2)
                events.write_text(json.dumps(dict(Action='fail', Package=MODULE, Elapsed=2)) + '\n')
                self.ci.summarize('root-core')
                self.assertIn('fail', summary.read_text())
                previous = summary.read_bytes()
                events.write_text(json.dumps(dict(Action='pass', Package=MODULE, Elapsed=2)) + '\n')
                self.ci.summarize('root-core')
                self.assertEqual(summary.read_bytes(), previous)


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
                        TEST_DIR='./missing', GIT_COMMIT='fixture', GIT_BRANCH='main', PREPARE_RESULT='success',
                        GITHUB_STEP_SUMMARY=str(self.root / 'job-summary.md'),
                        COVERAGE_ARTIFACT_NAME='caddy-security_coverage_fixture')
        shutil.copyfile(ROOT / 'Makefile', self.root / 'Makefile')
        scripts = self.root / 'assets/scripts'
        scripts.mkdir(parents=True)
        for name in ('ci_tests.py', 'ci_runtime_timings.json', 'ci_coverage_report.go', 'test_guard.py'):
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

    def test_matrix_cli_marks_composition_for_browser_setup(self):
        names = [
            'TestFuture', 'TestBrowser', 'TestAuthenticationClient',
            'TestAuthenticationClientNative', 'TestCaddyAuthenticatorE2E',
            'TestCaddySQLiteIdentityCommandsE2E', 'TestSecurityCredential',
            'TestDirectOAuthRefresh', 'TestCaddyDirectOAuthExpirationE2E',
            'TestOIDC', 'TestCaddyOIDCRelyingPartyE2E', 'TestJWKS',
            'TestAccessSigner', 'TestCaddyAccessSignerPersistenceE2E',
            'TestRefresh', 'TestSQLiteRefresh', 'TestOIDCRefreshBrowser',
            'TestCrossDeviceBrowser', 'TestCaddyCrossDeviceExpirationE2E',
            'TestCaddyCompositionE2E',
            *(f'TestAppFuture{number:02d}' for number in range(24)),
        ]
        inventory = self.root / 'tests.json'
        inventory.write_text(json.dumps(sorted(names)))
        matrix = json.loads(self.cli('matrix', '--inventory', str(inventory)).stdout)['include']
        runtime = [row for row in matrix if row['shard'] in RUNTIME_SHARDS]
        self.assertEqual(len(runtime), len(RUNTIME_SHARDS))
        self.assertEqual(sum(row['browser'] for row in runtime), 1,
                         'The composition parent must enable browser setup')

    def test_e2e_complete_disjoint_shards_reports_and_failed_rerun(self):
        expected = {
            **{name: [''] for name in ROOT_SHARDS},
            'packages': ['cmd/caddy-authenticator', 'cmd/server', 'pkg/future', 'pkg/enums'],
        }
        for directory in itertools.chain.from_iterable(expected.values()):
            self.package(directory, tested=directory not in ('pkg/enums', 'cmd/caddy-authenticator'))
        root_source = self.root
        (root_source / 'value.go').write_text(
            'package fixture\n' + ''.join(
                f'func {name}() int {{ return 42 }}\n'
                for name in ('Value', 'Challenge', 'Session', 'Protocol', 'Unused')))
        (root_source / 'value_test.go').write_text('''package fixture
import ("fmt"; "os"; "testing")
func TestE2ECrossDeviceBrowser(t *testing.T) {
 if Challenge() != 42 { t.Fatal("challenge") }
 t.Run("nested/Session", func(t *testing.T) { Challenge() })
}
func TestE2EDirectOAuth(t *testing.T) { Protocol() }
func TestE2EAuthenticationClient(t *testing.T) { Value() }
func TestCaddyAuthenticatorE2E(t *testing.T) { Value() }
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
func TestSkipped(t *testing.T) { t.Skip("retained skip") }
func ExampleValue() { fmt.Println(Value()); // Output: 42
}
func FuzzSessionSeeds(f *testing.F) {
 f.Add("seed")
 f.Fuzz(func(t *testing.T, input string) { Session() })
}
''')
        additional = [
            'TestAuthenticationClientNative', 'TestCaddySQLiteIdentityCommandsE2E',
            'TestSecurityCredential', 'TestCaddyDirectOAuthExpirationE2E',
            'TestCaddyCrossDeviceExpirationE2E', 'TestCaddyOIDCRelyingPartyE2E',
            'TestJWKS', 'TestAccessSigner', 'TestCaddyAccessSignerPersistenceE2E',
            'TestSQLiteRefresh', 'TestRefreshBrowser',
            *(f'TestAppRuntime{number:02d}' for number in range(23)),
        ]
        with (root_source / 'value_test.go').open('a') as stream:
            for name in additional:
                # Model a separately built CLI journey with zero parent counters.
                body = '' if name == 'TestCaddySQLiteIdentityCommandsE2E' else 'Value()'
                stream.write(f'func {name}(t *testing.T) {{ {body} }}\n')
        # Real preparation warms both fixture executables without running tests.
        for target in ('testdata/runtime_state_caddy', 'cmd/caddy-authenticator'):
            destination = self.root / target
            destination.mkdir(parents=True, exist_ok=True)
            if target.startswith('cmd/'):
                (destination / 'value.go').unlink()
            (destination / 'main.go').write_text('package main\nfunc main() {}\n')
        # Executable Go discovery respects build constraints, external test packages,
        # runnable examples and fuzz targets, rather than matching source text.
        (root_source / 'ignored_test.go').write_text(
            '//go:build neverenabled\n\npackage fixture\n'
            'func TestInvalidSyntax(\n')
        (root_source / 'external_test.go').write_text(
            'package fixture_test\nimport "testing"\n'
            'func TestExternalNewFeature(t *testing.T) {}\n')
        source = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.command('make', 'ci-prepare')
        prepared = self.root / 'reports with spaces/prepare'
        self.assertEqual(json.loads((prepared / 'resource-usage.json').read_text())['status'], 'passed')
        self.assertTrue((prepared / 'tests.json').is_file())
        self.assertTrue((self.root / 'tmp/ci-prepare/caddy').is_file())
        self.assertTrue((self.root / 'tmp/ci-prepare/caddy-authenticator').is_file())
        plan = json.loads(self.cli('plan').stdout)
        expected = {shard: sorted(MODULE + ('/' + path if path else '') for path in paths)
                    for shard, paths in expected.items()}
        self.assertEqual(plan, expected)
        matrix = json.loads(self.cli('matrix', '--inventory', str(prepared / 'tests.json')).stdout)['include']
        self.assertEqual([row['shard'] for row in matrix], list(SHARDS))
        self.assertEqual([row['cache_group'] for row in matrix],
                         ['root'] * 43 + ['packages'])
        self.assertEqual([row['shard'] for row in matrix if row['browser']],
                         ['root-browser', 'root-refresh-browser', 'root-cross-device'])
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
                actual = [e['Test'] for e in events if e['Action'] in ('pass', 'skip')
                          and e.get('Test') and '/' not in e['Test']]
                self.assertEqual(sorted(actual), names)
                discovery = json.loads((output / 'discovery/resource-usage.json').read_text())
                self.assertEqual(discovery['status'], 'passed')
            else:
                self.assertEqual(pattern, '.')
            self.assertEqual(command[-len(plan[shard]):], plan[shard])
            self.assertTrue((output / 'manifest.json').is_file())
            if shard == 'root-cli-identity':
                blocks = (output / 'coverage.out').read_text().splitlines()[1:]
                self.assertTrue(blocks)
                self.assertTrue(all(int(line.split()[-1]) == 0 for line in blocks))
            self.cli('summarize', shard)
            timing = json.loads((output / 'timing.json').read_text())
            self.assertEqual({p['package'] for p in timing['packages']}, set(plan[shard]))
            self.assertTrue(timing['slowest_tests'])
        job_summary = Path(self.env['GITHUB_STEP_SUMMARY'])
        self.assertFalse(job_summary.exists())
        self.cli('merge')
        self.assertFalse(job_summary.exists())
        combined = base / 'combined'
        summary = json.loads((combined / 'summary.json').read_text())
        self.assertEqual(summary['packages'], 5)
        self.assertEqual(summary['root_tests'], 50)
        self.assertEqual(summary['covered'], 6)
        self.assertEqual(summary['statements'], 8)
        self.assertAlmostEqual(summary['percent'], 100 * 6 / 8)
        report = base / 'report'
        timings = json.loads((report / 'timing.json').read_text())
        self.assertGreater(timings['wall_seconds'], 0)
        self.assertEqual({item['package'] for item in timings['packages']},
                         {package for group in plan.values() for package in group})
        expected_seconds = sum(item['seconds'] for shard in SHARDS for item in
                               json.loads((base / 'shards' / shard / 'timing.json').read_text())['packages'])
        self.assertAlmostEqual(timings['package_seconds'], expected_seconds)
        self.cli('summary')
        self.assertIn('### caddy-security_coverage_fixture', job_summary.read_text())
        self.assertIn('Entire module cumulative package time:', job_summary.read_text())
        self.assertIn('Test process wall span:', job_summary.read_text())
        for package in timings['packages']:
            self.assertIn(f'| `{package["directory"]}` | {package["seconds"]:.2f}', job_summary.read_text())
        self.assertIn('Entire module cumulative package time:', (report / 'index.html').read_text())
        self.assertIn('ci_tests.py summary', (ROOT / '.github/workflows/build.yml').read_text())
        unified = json.loads((report / 'summary.json').read_text())
        self.assertEqual(unified['outcome'], 'passed')
        self.assertEqual(unified['counts']['packages']['total'], 5)
        self.assertEqual(unified['counts']['tests']['skipped'], 1)
        self.assertEqual(unified['coverage']['statements'], summary['statements'])
        self.assertEqual(unified['coverage']['covered'], summary['covered'])
        self.assertFalse((report / 'run.json').exists())
        self.assertTrue(all(path.is_file() for path in report.iterdir()))
        self.assertIn('tested-coverage-theme-v1', (report / 'coverage.html').read_text())
        occurrences = {(package['name'], test['name']): test['status']
                       for package in unified['packages'] for test in package.get('tests', [])}
        expected_occurrences = {}
        for shard in SHARDS:
            for line in (base / 'shards' / shard / 'test_output.jsonl').read_text().splitlines():
                event = json.loads(line)
                if event.get('Test') and event['Action'] in ('pass', 'skip'):
                    expected_occurrences[event['Package'], event['Test']] = (
                        'passed' if event['Action'] == 'pass' else 'skipped')
        self.assertEqual(occurrences, expected_occurrences)
        self.assertEqual(unified['counts']['tests']['total'], len(expected_occurrences))
        cases = ET.parse(report / 'junit.xml').findall('.//testcase')
        self.assertEqual(len(cases), len(expected_occurrences))
        self.assertEqual(len([case for case in cases if case.find('skipped') is not None]), 1)
        provenance = json.loads((report / 'aggregation.json').read_text())
        self.assertEqual(set(provenance['sources']), set(SHARDS))
        manifest = json.loads((report / 'manifest.json').read_text())
        for entry in manifest['files']:
            data = (report / entry['name']).read_bytes()
            self.assertEqual(len(data), entry['size'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])

        # Package the actual workflow upload paths, so the primary download
        # opens directly while the separate diagnostic download retains shards.
        workflow = (ROOT / '.github/workflows/build.yml').read_text().split('  core:\n', 1)[1]
        for step, prefix, has_shards in (
                ('Upload unified test and coverage report', 'caddy-security_coverage_', False),
                ('Upload combined shard evidence', 'caddy-security_combined_coverage_', True)):
            upload = workflow.split(f'      - name: {step}\n', 1)[1].split('      - name:', 1)[0]
            self.assertIn('          name: ' + prefix + '${{', upload)
            upload_path = re.search(r'^          path: (.+)$', upload, re.MULTILINE).group(1)
            relative = Path(upload_path).relative_to('.coverage')
            archive = shutil.make_archive(str(self.root / prefix), 'zip', base / relative)
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
                self.assertIn('index.html', names)
                self.assertEqual(any(name.startswith('shards/') for name in names), has_shards)
                if not has_shards:
                    self.assertIn('coverage.html', names)
                    self.assertIn('test_output.html', names)
                    self.assertTrue(all('/' not in name for name in names))
        # Compare a real unsplit run: overlapping root blocks must sum their
        # counters and count source statements once, preserving the coverage union.
        self.command('make', 'test', 'TEST=.', 'TEST_DIR=./...', 'COVERAGE_DIR=unsplit')
        def profile(path):
            return sorted(path.read_text().splitlines())
        self.assertEqual(profile(combined / 'coverage.out'),
                         profile(self.root / 'unsplit/coverage.out'))
        self.assertEqual(profile(report / 'coverage.out'), profile(combined / 'coverage.out'))
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
        good_report = {path.name: path.read_bytes() for path in report.iterdir()}
        renderer = self.root / 'assets/scripts/ci_coverage_report.go'
        original_renderer = renderer.read_bytes()
        renderer.write_text('package main\nfunc broken(\n')
        self.cli('merge', success=False)
        renderer.write_bytes(original_renderer)
        self.assertEqual({path.name: path.read_bytes() for path in report.iterdir()}, good_report)
        self.assertEqual((combined / 'coverage.out').read_bytes(), good_profile)
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
                self.assertEqual({path.name: path.read_bytes() for path in report.iterdir()}, good_report)
            finally:
                path.write_bytes(original)
                manifest_path.write_bytes(original_manifest)
        corruptions = [
            ('run.json', lambda data: dict(data, capture_complete=False)),
            ('run.json', lambda data: dict(data, exit_code=1)),
            ('run.json', lambda data: dict(data, started_at='invalid')),
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

        for prepare in ('failure', 'cancelled', 'skipped', ''):
            self.cli('gate', env=dict(self.env, SELECTION_RESULT='success',
                                     GO_RESULT='success', QUALITY_RESULT='success',
                                     PREPARE_RESULT=prepare), success=False)

    def test_missing_graph_unknown_shard_and_incomplete_reports_fail(self):
        self.cli('plan', success=False)
        self.command('make', 'ci-prepare', success=False)
        self.command('make', 'ci-test-shard', 'CI_SHARD=typo', success=False)
        self.cli('merge', success=False)
        self.assertFalse((self.root / 'reports with spaces/combined').exists())
        self.cli('summarize', 'root-core')
        timing = json.loads((self.root / 'reports with spaces/shards/root-core/timing.json').read_text())
        self.assertTrue(timing['incomplete'])
        self.assertEqual(timing['packages'], [])


if __name__ == '__main__':
    unittest.main()
