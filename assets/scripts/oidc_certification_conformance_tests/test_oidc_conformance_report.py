"""Private HTML report, custom destination and failure-path coverage."""

from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "assets/scripts"))
import oidc_conformance as harness
from oidc_conformance_report import render_report


class Links(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.hrefs, self.tags = [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == 'a':
            self.hrefs.append(dict(attrs)['href'])


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='oidc-conformance-report-', dir=ROOT / 'tmp')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, data):
        harness.write_json(self.root / name, data)

    def test_optional_review_event_does_not_change_successful_callback_outcome(self):
        self.write('summary.json', {'modules': [{
            'id': 'callback', 'name': 'oidcc-ensure-request-object-with-redirect-uri',
            'result': 'PASSED', 'status': 'FINISHED', 'nonpass_events': [
                {'result': 'REVIEW', 'src': 'ExpectRedirectUriErrorPage', 'msg': 'Show redirect URI error page'}]}]})
        self.write('visual-evidence.json', [{'module_id': 'callback', 'unfilled_placeholder': 'optional-error-page'}])
        report = render_report(self.root)
        self.assertIn('badge passed', report)
        self.assertIn('REVIEW · ExpectRedirectUriErrorPage', report)
        self.assertIn('optional-error-page', report)
        self.assertIn('optional error-page placeholder can remain unfilled', report)
        self.assertNotIn('<summary><span class="badge review">', report)

    def test_consent_policy_explanation_only_for_recorded_deployments(self):
        self.assertNotIn('Caddy consent response policy', render_report(self.root))
        self.write('consent-policy.json', {'policy': 'same-origin'})
        (self.root / 'Caddyfile.redacted').touch()
        self.write('local-e2e.json', [])
        report = render_report(self.root)
        self.assertIn('Caddy consent response policy', report)
        self.assertIn('./consent-policy.json', Links(report).hrefs)
        self.assertIn('Origin and CSRF validation remain enabled', report)
        self.assertNotIn('All recorded modules passed', report)

        self.write('consent-policy.json', {'policy': 'same-origin', 'owner': 'provider'})
        report = render_report(self.root)
        self.assertIn('Caddy passes them through unchanged', report)
        self.assertNotIn('Caddy’s response matcher', report)
        self.assertIn('Origin and CSRF validation remain enabled', report)

    def test_report_preserves_all_outcomes_attempts_and_safe_relative_links(self):
        (self.root / 'instances').mkdir()
        (self.root / 'exports').mkdir()
        (self.root / 'visual').mkdir()
        outcomes = ['PASSED', 'WARNING', 'SKIPPED', 'REVIEW', 'FAILED', 'INTERRUPTED', 'UNKNOWN', 'FUTURE_RESULT']
        modules = []
        for i, outcome in enumerate(outcomes):
            self.write(f'instances/{i}.json', {'result': outcome})
            modules.append({'id': str(i), 'name': 'same-module', 'result': outcome, 'status': 'FINISHED',
                            'export': 'signed <capture>#.zip', 'nonpass_events': [
                                {'src': '<script>alert(1)</script>', 'result': outcome, 'msg': 'A < B & C'}]})
        (self.root / 'exports/signed <capture>#.zip').touch()
        (self.root / 'visual/actual page.txt').write_text('<script>private captured page</script>')
        self.write('visual-evidence.json', [{'module_id': '3', 'module': 'same-module', 'capture': 'actual page.txt'},
                                          {'module_id': 'other', 'unfilled_placeholder': 'pending review'}])
        self.write('summary.json', {'modules': modules, 'counts': dict.fromkeys(outcomes, 1), 'plans': 1,
                                  'not_run': [{'module': 'missing module', 'plan': 'p'}]})
        self.write('plan-p.json', {'planName': 'Basic OP', 'modules': [
            {'instances': list(map(str, range(8))), 'testModule': 'same-module'}, {'testModule': 'missing module'}]})
        self.write('execution.json', {'state': 'RUNNER_FINISHED', 'runner_exit_code': 7})
        (self.root / 'private.key').write_text('TOP SECRET VALUE')
        report = render_report(self.root)
        parsed = Links(report)
        for outcome in outcomes:
            self.assertIn(outcome, report)
        for i in range(8):
            self.assertIn(f'./instances/{i}.json', parsed.hrefs)
        self.assertIn('NOT_RUN: missing module', report)
        self.assertIn('pending review', report)
        self.assertIn('Original runner exit</dt><dd>7', report)
        self.assertIn('A &lt; B &amp; C', report)
        self.assertNotIn('script', parsed.tags)
        self.assertNotIn('TOP SECRET VALUE', report)
        self.assertIn('./private.key', parsed.hrefs)
        self.assertIn('./exports/signed%20%3Ccapture%3E%23.zip', parsed.hrefs)
        self.assertNotIn('All recorded modules passed', report)
        for href in parsed.hrefs:
            if href.startswith('#') or href == './evidence-sha256.json':
                continue
            self.assertTrue(href.startswith('./'), href)
            self.assertTrue((self.root / unquote(href)).is_file(), href)

    def test_interruption_and_incomplete_evidence_cannot_display_all_passed(self):
        modules = [{'id': str(i), 'name': 'module', 'result': 'PASSED', 'status': 'FINISHED'} for i in range(71)]
        self.write('summary.json', {'modules': modules, 'plans': 3, 'not_run': []})
        for i in range(3):
            self.write(f'plan-{i}.json', {'planName': str(i), 'modules': [
                {'instances': [m['id'] for m in modules[i::3]]}]})
        status = {'state': 'RUNNER_FINISHED', 'runner_exit_code': 0, 'all_passed': True}
        self.write('execution.json', status)
        self.assertIn('All recorded modules passed', render_report(self.root))
        for change in ({'interruption': 'TimeoutExpired'}, {'runner_exit_code': 1}, {'state': 'EVIDENCE_ERROR'}):
            self.write('execution.json', dict(status, **change))
            self.assertNotIn('All recorded modules passed', render_report(self.root))
        self.write('execution.json', status)
        (self.root / 'plan-2.json').unlink()
        self.assertNotIn('All recorded modules passed', render_report(self.root))

    def test_blocker_report_is_private_hashed_and_keeps_failure_status(self):
        status = {'state': 'BLOCKED', 'blocker': 'missing pinned suite checkout', 'runner_exit_code': None}
        result = harness.finish_evidence(self.root, harness.Processes(self.root), status, 2)
        report = self.root / 'index.html'
        self.assertEqual(result, 2)
        self.assertIn(status['blocker'], report.read_text())
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        manifest = json.loads((self.root / 'evidence-sha256.json').read_text())
        self.assertEqual(manifest['index.html'], harness.digest(report))
        self.assertEqual(json.loads((self.root / 'execution.json').read_text())['state'], 'BLOCKED')

    def test_report_failure_preserves_runner_exit_and_fails_successful_command(self):
        for original, expected in ((7, 7), (0, 2)):
            with mock.patch.object(harness, 'render_report', side_effect=ValueError('broken evidence')):
                status = {'state': 'RUNNER_FINISHED', 'runner_exit_code': original}
                result = harness.finish_evidence(self.root, harness.Processes(self.root), status, original)
            self.assertEqual(result, expected)
            recorded = json.loads((self.root / 'execution.json').read_text())
            self.assertEqual(recorded['runner_exit_code'], original)
            self.assertEqual(recorded['state'], 'EVIDENCE_ERROR')
            self.assertTrue((self.root / 'report.private.log').is_file())

    def test_report_rejects_escape_links_and_survives_broken_optional_json(self):
        self.write('summary.json', {'modules': [{'id': '../escape', 'name': '<b>module</b>',
                                               'result': 'REVIEW', 'export': '../../outside.zip'}]})
        (self.root / 'candidate.json').write_text('{broken')
        (self.root / 'outside-link').symlink_to(ROOT / 'go.mod')
        report = render_report(self.root)
        self.assertIn('unsafe evidence path', report)
        self.assertIn('Cannot read candidate.json', report)
        parsed = Links(report)
        self.assertNotIn('b', parsed.tags)
        self.assertNotIn('./outside-link', parsed.hrefs)
        self.assertFalse(any('..' in href for href in parsed.hrefs))

    def test_make_passes_custom_destination_literally(self):
        # Exercise the actual Make recipe without recursively launching its
        # unit tests or depending on the external suite inside a unit test.
        record = self.root / 'args.json'
        recorder = self.root / 'record-python'
        recorder.write_text(f'#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n'
                            f'Path({str(record)!r}).write_text(json.dumps(sys.argv[1:]))\n')
        recorder.chmod(0o700)
        destination = str(self.root / 'new parent' / 'quote" and `literal`')
        env = os.environ.copy()
        env.pop('MAKEFLAGS', None)
        env.pop('MFLAGS', None)
        result = subprocess.run(['make', '--no-print-directory', 'oidc-conformance-test',
                                 'PYTHON=' + str(recorder), 'CONFORMANCE_RESULTS=' + destination],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(record.read_text())
        self.assertEqual(args[args.index('--results') + 1], destination)


if __name__ == '__main__':
    unittest.main()
