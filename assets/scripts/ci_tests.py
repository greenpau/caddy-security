#!/usr/bin/env python3
"""Run exhaustive Go test/package shards and verify their CI evidence."""

import argparse
from datetime import datetime
from functools import lru_cache
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_SHARDS = tuple(f'root-runtime-{number:02d}' for number in range(1, 25))
ROOT_SHARDS = ('root-direct-oauth-expiry', 'root-cross-device-expiry',
               'root-core', 'root-browser', 'root-clients-legacy', 'root-clients-native',
               'root-cli-authenticator', 'root-cli-identity', 'root-cli-commands',
               'root-direct-oauth', 'root-oidc', 'root-oidc-rp', 'root-jwks',
               'root-access-signers', 'root-access-signers-persistence',
               'root-refresh', 'root-refresh-sqlite', 'root-refresh-browser',
               'root-cross-device', *RUNTIME_SHARDS)
SHARDS = (*ROOT_SHARDS, 'packages')
BROWSER_SHARDS = ('root-browser', 'root-direct-oauth', 'root-refresh-browser',
                  'root-refresh-sqlite', 'root-cross-device', *RUNTIME_SHARDS)
BROWSER_TESTS = {'TestCaddyDirectOAuthE2E', 'TestCaddyConnectedAccountsE2E',
                 'TestCaddyDocumentsE2E', 'TestCaddySQLiteIdentityE2E',
                 'TestCaddySQLiteRegistrationE2E', 'TestCaddySQLiteTicketE2E',
                 'TestCaddySQLiteRefreshUncertaintyE2E'}
TESTED_FILES = {'coverage.html', 'coverage.out', 'index.html', 'junit.xml', 'run.json',
                'stderr.log', 'summary.json', 'test_output.html', 'test_output.jsonl'}


def packages():
    result = subprocess.run(['go', 'list', '-mod=readonly', '-e', '-json', './...'],
                            cwd=ROOT, check=True, capture_output=True, text=True, timeout=120)
    decoder = json.JSONDecoder()
    data = result.stdout.lstrip()
    found = {}
    while data:
        package, end = decoder.raw_decode(data)
        if package.get('Error') or package.get('DepsErrors'):
            raise ValueError('Go package graph contains errors')
        name = package['ImportPath']
        if not re.fullmatch(r'[A-Za-z0-9_./~\-]+', name) or name in found:
            raise ValueError('Invalid or duplicate Go package path')
        Path(package['Dir']).resolve().relative_to(ROOT.resolve())
        found[name] = package
        data = data[end:].lstrip()
    if not found:
        raise ValueError('No Go packages discovered')
    return found


def partition(graph):
    """Split the root package by test; discover every other package automatically."""
    result = {name: [] for name in SHARDS}
    for name, package in sorted(graph.items()):
        directory = Path(package['Dir']).resolve().relative_to(ROOT.resolve()).as_posix()
        if directory == '.':
            for shard in ROOT_SHARDS:
                result[shard].append(name)
        else:
            result['packages'].append(name)
    if any(not group for group in result.values()):
        raise ValueError('Expected nonempty CI package shards')
    return result


@lru_cache(maxsize=1)
def runtime_timings():
    data = json.loads((ROOT / 'assets/scripts/ci_runtime_timings.json').read_text())
    if data['schema'] != 'caddy-security/ci-runtime-timings/v1':
        raise ValueError('Unsupported runtime timing inventory')
    values = data['seconds']
    for name, seconds in (*values.items(), *data['split_parent_seconds'].items()):
        if (not re.fullmatch(r'(Test|Example|Fuzz)\w*', name)
                or not isinstance(seconds, (int, float)) or not math.isfinite(seconds)
                or seconds <= 0):
            raise ValueError('Invalid runtime timing entry')
    # Each independent local-identity group initially uses one third of the
    # former combined parent duration; replace estimates after hosted evidence.
    estimate = data['split_parent_seconds']['TestCaddyLocalIdentityE2E'] / 3
    return {**values, **dict.fromkeys(('TestCaddyLocalIdentityE2E',
                                      'TestCaddyLocalIdentityMFAE2E',
                                      'TestCaddyLocalIdentityMutationE2E'), estimate)}


def runtime_weight(name):
    """Use recorded CI durations with conservative fallbacks for new parents."""
    measured = runtime_timings().get(name)
    if measured is not None:
        return measured
    if name.startswith('TestCaddy') and name.endswith('E2E'):
        return 90
    return 2 if name.startswith('TestApp') else 1


def root_partition(names):
    """Keep top-level tests intact and balance remaining runtime journeys."""
    if (not names or names != sorted(set(names))
            or any(not re.fullmatch(r'(Test|Example|Fuzz)\w*', name) for name in names)):
        raise ValueError('Invalid root test inventory')
    groups = {name: [] for name in ROOT_SHARDS}
    runtime = []
    for name in names:
        if 'CrossDeviceExpiration' in name:
            shard = 'root-cross-device-expiry'
        elif 'CrossDevice' in name:
            shard = 'root-cross-device'
        elif 'DirectOAuthExpiration' in name:
            shard = 'root-direct-oauth-expiry'
        elif 'DirectOAuth' in name:
            shard = 'root-direct-oauth'
        elif 'AuthenticationClientNative' in name:
            shard = 'root-clients-native'
        elif 'AuthenticationClient' in name:
            shard = 'root-clients-legacy'
        elif 'SQLiteIdentityCommands' in name:
            shard = 'root-cli-identity'
        elif 'CaddyAuthenticator' in name:
            shard = 'root-cli-authenticator'
        elif 'Authenticator' in name or 'SecurityCredential' in name or 'CommandsE2E' in name:
            shard = 'root-cli-commands'
        elif 'Refresh' in name:
            if 'Browser' in name:
                shard = 'root-refresh-browser'
            elif 'SQLiteRefresh' in name or 'RefreshStore' in name:
                shard = 'root-refresh-sqlite'
            else:
                shard = 'root-refresh'
        elif 'AccessSignerPersistence' in name:
            shard = 'root-access-signers-persistence'
        elif 'AccessSigner' in name:
            shard = 'root-access-signers'
        elif 'JWKS' in name:
            shard = 'root-jwks'
        elif 'OIDCRelyingParty' in name:
            shard = 'root-oidc-rp'
        elif 'OIDC' in name:
            shard = 'root-oidc'
        elif 'Browser' in name:
            shard = 'root-browser'
        elif name.startswith(('TestApp', 'TestCaddy')):
            runtime.append(name)
            continue
        else:
            shard = 'root-core'
        groups[shard].append(name)
    # Longest-first assignment spreads measured long journeys across runners. New names participate automatically; lexical tie breaks are stable.
    weights = dict.fromkeys(RUNTIME_SHARDS, 0)
    for name in sorted(runtime, key=lambda name: (-runtime_weight(name), name)):
        shard = min(RUNTIME_SHARDS, key=lambda shard: (weights[shard], shard))
        groups[shard].append(name)
        weights[shard] += runtime_weight(name)
    for selected in groups.values():
        selected.sort()
    if any(not group for group in groups.values()):
        raise ValueError('Expected nonempty root test shards')
    return groups


def matrix(names=None):
    groups = root_partition(names) if names is not None else None
    return dict(include=[dict(
        shard=shard, cache_group=shard.split('-')[0],
        browser=(any('Browser' in name or name in BROWSER_TESTS
                     for name in groups[shard]) if groups is not None and shard in groups
                 else shard in BROWSER_SHARDS)) for shard in SHARDS])


def prepare():
    """Compile shared race/coverage and Caddy fixtures once without running tests."""
    plan = partition(packages())
    output = coverage_directory() / 'prepare'
    output.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, str(ROOT / 'assets/scripts/test_guard.py'), 'run',
         sys.executable, str(Path(__file__).resolve()), 'warm',
         plan[ROOT_SHARDS[0]][0], str(output)], cwd=ROOT,
        env=dict(os.environ, COVERAGE_DIR=str(output))).returncode


def warm(package, output):
    inventory(package, output)
    binaries = ROOT / 'tmp/ci-prepare'
    binaries.mkdir(parents=True, exist_ok=True)
    for flags, target, name in (
            (['-trimpath'], './testdata/runtime_state_caddy', 'caddy'),
            (['-race'], './cmd/caddy-authenticator', 'caddy-authenticator')):
        subprocess.run(['go', 'build', '-mod=readonly', *flags,
                        '-o', str(binaries / name), target], cwd=ROOT,
                       check=True, timeout=240)


def inventory(package, output):
    """Run only under the resource guard; ask Go about runnable tests, not source regexes."""
    output.mkdir(parents=True, exist_ok=True)
    # Match the race/coverage build used by tested so the compiled cache is reusable.
    with (output / 'listing.txt').open('w') as stream:
        subprocess.run(['go', 'test', '-mod=readonly', '-race', '-covermode=atomic',
                        '-count=1', '-list=^(Test|Example|Fuzz)', package], cwd=ROOT,
                       stdout=stream, check=True, timeout=300)
    names = sorted(line for line in (output / 'listing.txt').read_text().splitlines()
                   if re.fullmatch(r'(Test|Example|Fuzz)\w*', line))
    root_partition(names)
    (output / 'tests.json').write_text(json.dumps(names, indent=2) + '\n')


def coverage_directory():
    # Discovery and Make execute in ROOT even when the script is invoked elsewhere.
    output = (ROOT / Path(os.environ.get('COVERAGE_DIR', '.coverage'))).resolve()
    output.relative_to(ROOT.resolve())
    return output


def directory(shard):
    return coverage_directory() / 'shards' / shard


def run(shard):
    output = directory(shard)
    output.mkdir(parents=True, exist_ok=True)
    selection_path = output / 'selection.json'
    # An early discovery/build/guard failure must invalidate an older successful run.
    selection_path.write_text(json.dumps(dict(shard=shard, complete=False)) + '\n')
    plan = partition(packages())
    selection = dict(schema='caddy-security/ci-selection/v2', shard=shard, complete=False,
                     packages=plan[shard], all_shards=plan)
    pattern = '.'
    if shard in ROOT_SHARDS:
        discovery = output / 'discovery'
        subprocess.run([sys.executable, str(ROOT / 'assets/scripts/test_guard.py'), 'run',
                        sys.executable, str(Path(__file__).resolve()), 'inventory',
                        plan[shard][0], str(discovery)], cwd=ROOT, check=True,
                       env=dict(os.environ, COVERAGE_DIR=str(discovery)))
        names = json.loads((discovery / 'tests.json').read_text())
        selected = root_partition(names)[shard]
        selection.update(root_tests=names, selected_tests=selected)
        # Make expands command-line variables: $$ preserves the final regex anchor.
        pattern = '^(' + '|'.join(selected) + ')$$'
    selection_path.write_text(json.dumps(selection, indent=2) + '\n')
    print(f'Running {shard}: {len(plan[shard])} package(s)', flush=True)
    # Explicit Make arguments override inherited filters, including MAKEFLAGS.
    result = subprocess.run(['make', 'test', 'TEST=' + pattern,
                             'TEST_DIR=' + ' '.join(plan[shard]),
                             # External-binary journeys can have no parent hits.
                             # The complete merged suite enforces the 1% policy.
                             'MINIMUM_COVERAGE=0', 'COVERAGE_DIR=' + str(output)], cwd=ROOT)
    selection['complete'] = result.returncode == 0
    selection_path.write_text(json.dumps(selection, indent=2) + '\n')
    return result.returncode if result.returncode >= 0 else 1


def read_events(path):
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def summarize(shard):
    output = directory(shard)
    resource_path = output / 'resource-usage.json'
    resource = json.loads(resource_path.read_text()) if resource_path.exists() else {}
    completed, tests = [], []
    incomplete = ''
    selection_path = output / 'selection.json'
    if selection_path.exists() and not json.loads(selection_path.read_text()).get('complete'):
        incomplete = 'Shard did not complete successfully; reports may be from an earlier attempt.'
    try:
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Action') not in ('pass', 'fail', 'skip'):
                continue
            item = dict(package=event['Package'], outcome=event['Action'],
                        seconds=event.get('Elapsed', 0))
            if not event.get('Test'):
                completed.append(item)
            elif '/' not in event['Test']:
                tests.append(dict(item, test=event['Test']))
    except (FileNotFoundError, json.JSONDecodeError):
        incomplete = 'Test output is missing or incomplete; inspect the raw evidence.'
    timing = dict(shard=shard, resources=resource, incomplete=incomplete,
                  packages=sorted(completed, key=lambda item: item['seconds'], reverse=True),
                  slowest_tests=sorted(tests, key=lambda item: item['seconds'], reverse=True)[:20])
    output.mkdir(parents=True, exist_ok=True)
    (output / 'timing.json').write_text(json.dumps(timing, indent=2) + '\n')
    lines = [f'### Go tests: {shard}', '',
             f"Guard status: **{resource.get('status', 'unavailable')}**. "
             f"Elapsed: {resource.get('elapsed_seconds', '?')}s. "
             f"Peak memory: {resource.get('peak_memory_mib', '?')} MiB.", '']
    if resource.get('reason') or incomplete:
        lines.extend([resource.get('reason') or incomplete, ''])
    lines.extend(['| Package | Seconds | Result |', '| --- | ---: | --- |'])
    for item in timing['packages'][:10]:
        lines.append(f"| {item['package']} | {item['seconds']:.2f} | {item['outcome']} |")
    text = '\n'.join(lines) + '\n'
    print(text)
    failed = (resource.get('status') != 'passed' or incomplete
              or any(item['outcome'] == 'fail' for item in completed))
    if failed and os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as summary:
            summary.write(text)


def gate():
    """A failed or unexpectedly skipped dependency must fail the stable check."""
    results = {name: os.environ.get(name) for name in
               ('SELECTION_RESULT', 'GO_RESULT', 'QUALITY_RESULT', 'PREPARE_RESULT')}
    if any(result != 'success' for result in results.values()):
        raise ValueError(f'Incomplete validation: {results}')
    print('All Go shards, shared preparation and repository quality gates passed.')


def verify_manifest(output):
    """Keep each downloaded tested generation complete and internally consistent."""
    manifest = json.loads((output / 'manifest.json').read_text())
    if manifest['version'] != 1 or manifest['algorithm'] != 'sha256':
        raise ValueError('Unsupported tested manifest')
    names = set()
    for entry in manifest['files']:
        name = entry['name']
        if name in names or Path(name).name != name or name in ('', '.', '..'):
            raise ValueError('Invalid tested artifact name')
        names.add(name)
        path = output / name
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if path.stat().st_size != entry['size'] or digest.hexdigest() != entry['sha256']:
            raise ValueError(f'Tested artifact integrity mismatch: {name}')
    if not TESTED_FILES <= names:
        raise ValueError('Incomplete tested manifest')


def report_events(base, root_package):
    """Project disjoint test events into one package lifecycle per package.

    Root package elapsed time is cumulative shard work, not parallel wall time.
    Original byte-for-byte streams remain in the separate evidence bundle.
    """
    start, terminal = None, None
    elapsed = 0
    for shard in SHARDS:
        for event in read_events(base / 'shards' / shard / 'test_output.jsonl'):
            if event.get('Package') == root_package and not event.get('Test'):
                if event['Action'] == 'start':
                    if start is None or event.get('Time', '') < start.get('Time', ''):
                        start = dict(event)
                if event['Action'] in ('pass', 'skip'):
                    elapsed += event.get('Elapsed', 0)
                    if terminal is None or event.get('Time', '') > terminal.get('Time', ''):
                        terminal = dict(event)
    if terminal is None:
        raise ValueError('Missing aggregate root package outcome')
    if start is not None:
        yield start
    for shard in SHARDS:
        for event in read_events(base / 'shards' / shard / 'test_output.jsonl'):
            if (event.get('Package') == root_package and not event.get('Test')
                    and event['Action'] in ('start', 'pass', 'skip')):
                continue
            yield event
    yield dict(terminal, Action='pass', Elapsed=elapsed)


def package_timings(base, root_package):
    """Measure the parallel process span separately from cumulative package work."""
    starts, finishes, packages = [], [], {}
    for shard in SHARDS:
        output = base / 'shards' / shard
        execution = json.loads((output / 'run.json').read_text())
        start, finish = [datetime.fromisoformat(execution[name].replace('Z', '+00:00'))
                         for name in ('started_at', 'finished_at')]
        if start.tzinfo is None or finish.tzinfo is None or finish < start:
            raise ValueError(f'Invalid process timing for {shard}')
        starts.append(start)
        finishes.append(finish)
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Test') or event.get('Action') not in ('pass', 'skip'):
                continue
            name = event['Package']
            seconds = event.get('Elapsed', 0)
            if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds < 0:
                raise ValueError(f'Invalid package timing for {name}')
            package = packages.setdefault(name, dict(
                package=name, directory='.' if name == root_package else name[len(root_package) + 1:],
                seconds=0, outcome='skip'))
            package['seconds'] += seconds
            if event['Action'] == 'pass':
                package['outcome'] = 'pass'
    return dict(schema='caddy-security/ci-timing/v1',
                started_at=min(starts).isoformat(), finished_at=max(finishes).isoformat(),
                wall_seconds=(max(finishes) - min(starts)).total_seconds(),
                package_seconds=sum(package['seconds'] for package in packages.values()),
                packages=[packages[name] for name in sorted(packages)])


def timing_markdown(timing, summary):
    name = os.environ.get('COVERAGE_ARTIFACT_NAME', 'caddy-security_coverage')
    lines = [f'### {name}', '',
             f'Merged coverage: **{summary["percent"]:.2f}%** '
             f'({summary["covered"]}/{summary["statements"]} statements).', '',
             f'Test process wall span: **{timing["wall_seconds"]:.2f}s** '
             '(first shard start to last shard finish).',
             f'Entire module cumulative package time: **{timing["package_seconds"]:.2f}s**.', '',
             'Package times sum parallel shard executions; they are not wall time.', '',
             '| Directory | Seconds | Result |', '| --- | ---: | --- |']
    for package in timing['packages']:
        lines.append(f'| `{package["directory"]}` | {package["seconds"]:.2f} '
                     f'| {package["outcome"]} |')
    return '\n'.join(lines) + '\n'


def publish_summary():
    text = (coverage_directory() / 'report/timing.md').read_text()
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
            stream.write(text)


def publish_report(base, root_package, profile, summary, timing):
    """Render one standalone report without inventing a tested child run."""
    with tempfile.TemporaryDirectory(prefix='.ci-report-', dir=base) as temporary:
        staging = Path(temporary)
        (staging / 'coverage.out').write_text(profile)
        with (staging / 'test_output.jsonl').open('w', encoding='utf-8') as stream:
            for event in report_events(base, root_package):
                stream.write(json.dumps(event) + '\n')
        with (staging / 'stderr.log').open('wb') as stream:
            for shard in SHARDS:
                path = base / 'shards' / shard / 'stderr.log'
                if path.stat().st_size:
                    stream.write(f'\n--- {shard} ---\n'.encode())
                    with path.open('rb') as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b''):
                            stream.write(chunk)
        provenance = dict(summary, schema='caddy-security/ci-report/v1',
                          package_elapsed='cumulative shard seconds',
                          event_stream='projection; original streams retained in shard evidence',
                          sources={name: dict(manifest_sha256=hashlib.sha256(
                              (base / 'shards' / name / 'manifest.json').read_bytes()).hexdigest())
                              for name in SHARDS})
        (staging / 'aggregation.json').write_text(json.dumps(provenance, indent=2) + '\n')
        (staging / 'timing.json').write_text(json.dumps(timing, indent=2) + '\n')
        (staging / 'timing.md').write_text(timing_markdown(timing, summary))
        subprocess.run(['go', 'run', '-mod=readonly', 'assets/scripts/ci_coverage_report.go',
                        str(staging)], cwd=ROOT, check=True, timeout=300)
        rows = ''.join(f'<tr><td>{html.escape(package["directory"])}</td>'
                       f'<td>{package["seconds"]:.2f}</td><td>{package["outcome"]}</td></tr>'
                       for package in timing['packages'])
        timings_html = ('<section aria-label="Package timings"><h2>Package timings</h2>'
                        f'<p>Test process wall span: {timing["wall_seconds"]:.2f}s. '
                        f'Entire module cumulative package time: {timing["package_seconds"]:.2f}s.</p>'
                        '<p>Package times sum parallel shard executions; they are not wall time.</p>'
                        '<table><thead><tr><th>Directory</th><th>Seconds</th><th>Result</th></tr></thead>'
                        f'<tbody>{rows}</tbody></table></section>')
        index = staging / 'index.html'
        index.write_text(index.read_text().replace('</body>', timings_html + '</body>', 1))
        entries = []
        for path in sorted(staging.iterdir()):
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            entries.append(dict(name=path.name, size=path.stat().st_size, sha256=digest.hexdigest()))
        (staging / 'manifest.json').write_text(json.dumps(dict(
            schema='caddy-security/ci-report-manifest/v1', version=1,
            algorithm='sha256', files=entries), indent=2) + '\n')
        output = base / 'report'
        output.mkdir(parents=True, exist_ok=True)
        for path in staging.iterdir():
            path.replace(output / path.name)


def merge():
    """Verify full execution and sum counters for intentional root overlap only."""
    base = coverage_directory()
    plan = None
    root_package = None
    root_tests = None
    root_blocks = None
    blocks = {}
    mode = None
    for shard in SHARDS:
        output = directory(shard)
        selected = json.loads((output / 'selection.json').read_text())
        if not selected['complete']:
            raise ValueError(f'Unfinished shard execution: {shard}')
        current_plan = selected['all_shards']
        if (selected['schema'] != 'caddy-security/ci-selection/v2'
                or set(current_plan) != set(SHARDS)
                or any(not group or group != sorted(set(group))
                       for group in current_plan.values())):
            raise ValueError('Incomplete shard plan')
        if plan is not None and plan != current_plan:
            raise ValueError('Shards were not produced from the same package plan')
        plan = current_plan
        if root_package is None:
            if any(len(plan[name]) != 1 for name in ROOT_SHARDS):
                raise ValueError('Root test shards must each select one package')
            root_package = plan[ROOT_SHARDS[0]][0]
            if any(plan[name] != [root_package] for name in ROOT_SHARDS):
                raise ValueError('Root test shards must share the same package')
            others = [package for name in SHARDS if name not in ROOT_SHARDS
                      for package in plan[name]]
            if len(set(others)) != len(others) or root_package in others:
                raise ValueError('Unexpected package overlap')
        if selected['shard'] != shard or selected['packages'] != plan[shard]:
            raise ValueError(f'Package selection mismatch for {shard}')
        expected_tests = None
        if shard in ROOT_SHARDS:
            names = selected['root_tests']
            discovery = output / 'discovery'
            if (json.loads((discovery / 'resource-usage.json').read_text())['status'] != 'passed'
                    or json.loads((discovery / 'tests.json').read_text()) != names):
                raise ValueError(f'Incomplete root discovery for {shard}')
            expected_tests = root_partition(names)[shard]
            if selected['selected_tests'] != expected_tests:
                raise ValueError(f'Incorrect root test selection for {shard}')
            if root_tests is not None and root_tests != names:
                raise ValueError('Root shards disagree about the test inventory')
            root_tests = names
        verify_manifest(output)
        execution = json.loads((output / 'run.json').read_text())
        resource = json.loads((output / 'resource-usage.json').read_text())
        if (execution['exit_code'] != 0 or not execution['capture_complete']
                or not execution['child_started'] or resource['status'] != 'passed'):
            raise ValueError(f'Unsuccessful or incomplete evidence for {shard}')
        terminals, test_terminals = {}, set()
        for event in read_events(output / 'test_output.jsonl'):
            if event.get('Action') == 'fail':
                raise ValueError(f'Failed test evidence for {shard}')
            if not event.get('Test') and event.get('Action') in ('pass', 'skip'):
                name = event['Package']
                if name in terminals:
                    raise ValueError(f'Duplicate package execution: {name}')
                terminals[name] = event['Action']
            if (expected_tests is not None and event.get('Test')
                    and '/' not in event['Test'] and event.get('Action') in ('pass', 'skip')):
                name = event['Test']
                if event['Package'] != root_package or name in test_terminals:
                    raise ValueError(f'Unexpected or duplicate root test: {name}')
                test_terminals.add(name)
        if set(terminals) != set(plan[shard]):
            raise ValueError(f'Not every selected package completed in {shard}')
        if expected_tests is not None and test_terminals != set(expected_tests):
            raise ValueError(f'Not every selected root test completed exactly once in {shard}')
        shard_blocks = {}
        with (output / 'coverage.out').open(encoding='utf-8') as profile:
            header = profile.readline().strip()
            if header != 'mode: atomic' or (mode is not None and mode != header):
                raise ValueError('Expected race-enabled atomic coverage profiles')
            mode = header
            for line in profile:
                block, statements, count = line.split()
                statements, count = int(statements), int(count)
                owner = block.rsplit(':', 1)[0].rsplit('/', 1)[0]
                if (statements < 0 or count < 0 or block in shard_blocks
                        or owner not in plan[shard]):
                    raise ValueError(f'Invalid or overlapping coverage block: {block}')
                shard_blocks[block] = statements
                if block in blocks:
                    if (shard not in ROOT_SHARDS or owner != root_package
                            or statements != blocks[block][0]):
                        raise ValueError(f'Unexpected coverage overlap: {block}')
                    count += blocks[block][1]
                blocks[block] = (statements, count)
        if shard in ROOT_SHARDS:
            if not shard_blocks or (root_blocks is not None and root_blocks != shard_blocks):
                raise ValueError('Root coverage profiles have different source blocks')
            root_blocks = shard_blocks
    all_packages = {name for group in plan.values() for name in group}
    total = sum(statements for statements, _ in blocks.values())
    covered = sum(statements for statements, count in blocks.values() if count > 0)
    if not total or covered * 100 < total:
        raise ValueError('Combined coverage is below the 1 percent nonempty-profile policy')
    summary = dict(schema='caddy-security/ci-coverage/v2', packages=len(all_packages),
                   root_tests=len(root_tests),
                   shards=plan, covered=covered, statements=total, percent=100 * covered / total)
    # Shard manifests stay intact. This is an aggregate, not a fabricated tested run.
    output = base / 'combined'
    output.mkdir(parents=True, exist_ok=True)
    profile = mode + '\n' + ''.join(
        f'{block} {statements} {count}\n' for block, (statements, count) in sorted(blocks.items()))
    timing = package_timings(base, root_package)
    publish_report(base, root_package, profile, summary, timing)
    (output / 'coverage.out').write_text(profile)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    links = ''.join(f'<li><a href="../shards/{name}/index.html">{html.escape(name)}</a>'
                    f' ({len(plan[name])} packages)</li>' for name in SHARDS)
    (output / 'index.html').write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Caddy Security CI coverage</title>'
        '<h1>Caddy Security CI coverage</h1>'
        f'<p>{len(all_packages)} packages passed; {covered}/{total} statements covered '
        f'({summary["percent"]:.2f}%).</p><ul>{links}</ul>'
        '<p><a href="coverage.out">Combined Go coverage profile</a></p></html>\n')
    (base / 'index.html').write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<title>Caddy Security CI reports</title><h1>Caddy Security CI reports</h1>'
        '<p><a href="report/index.html">Unified test and coverage report</a></p>'
        '<p><a href="combined/index.html">Complete suite and combined coverage</a></p>\n')
    text = f"Full suite: {len(all_packages)} packages; combined coverage {summary['percent']:.2f}%.\n"
    print(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('matrix').add_argument('--inventory', type=Path)
    commands.add_parser('plan')
    commands.add_parser('prepare')
    warming = commands.add_parser('warm')
    warming.add_argument('package')
    warming.add_argument('output', type=Path)
    listing = commands.add_parser('inventory')
    listing.add_argument('package')
    listing.add_argument('output', type=Path)
    for command in ('run', 'summarize'):
        commands.add_parser(command).add_argument('shard', choices=SHARDS)
    commands.add_parser('gate')
    commands.add_parser('merge')
    commands.add_parser('summary')
    args = parser.parse_args()
    if args.command == 'matrix':
        names = json.loads(args.inventory.read_text()) if args.inventory else None
        print(json.dumps(matrix(names)))
    elif args.command == 'prepare':
        return prepare()
    elif args.command == 'warm':
        warm(args.package, args.output)
    elif args.command == 'inventory':
        inventory(args.package, args.output)
    elif args.command == 'plan':
        print(json.dumps(partition(packages()), indent=2))
    elif args.command == 'run':
        return run(args.shard)
    elif args.command == 'summarize':
        summarize(args.shard)
    elif args.command == 'gate':
        gate()
    elif args.command == 'summary':
        publish_summary()
    else:
        merge()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'CI tests: {error}', file=sys.stderr)
        sys.exit(1)
