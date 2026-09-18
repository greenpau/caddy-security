"""Screenshot provenance, image-slot binding, real-network display and TLS guards."""

import base64
from contextlib import closing
import json
import hashlib
import sqlite3
import ssl
import stat
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'assets/scripts'))
import oidc_conformance as harness
from oidc_conformance_browser import expected_slot, page_kind, Chrome, Reviewer, trust_ca, MAX_SCREENSHOT_BYTES
from oidc_conformance_browser_tools import extract_zip
from oidc_conformance_review_report import network_rows, render_reviews, consent_diagnosis

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')


class ReviewBrowserTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='oidc-conformance-browser-', dir=ROOT / 'tmp')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_screenshot_must_match_requested_page_and_second_authorization(self):
        login = {'src': 'ExpectSecondLoginPage', 'upload': 'second-login'}
        error = {'src': 'ExpectRedirectUriErrorPage', 'upload': 'redirect-error'}
        for name in ('oidcc-prompt-login', 'oidcc-max-age-1'):
            self.assertIsNone(expected_slot(name, 1, 'login', [login]))
            self.assertIsNone(expected_slot(name, 2, 'callback', [login]))
            self.assertEqual(expected_slot(name, 2, 'login', [error, login]), login)
            for slots in ([], [error], [login, login]):
                with self.assertRaises(harness.Blocker):
                    expected_slot(name, 2, 'login', slots)
        self.assertIsNone(expected_slot('oidcc-ensure-registered-redirect-uri', 1, 'login', [error]))
        self.assertEqual(expected_slot('oidcc-ensure-registered-redirect-uri', 1, 'rejected', [error]), error)

    def test_driver_requests_strict_tls_and_rejects_insecure_capability(self):
        with mock.patch.object(Chrome, 'request', return_value={
                'sessionId': 'x', 'capabilities': {'acceptInsecureCerts': True, 'browserVersion': '153.0.8010.47'}}) as request:
            with self.assertRaisesRegex(harness.Blocker, 'certificate validation'):
                Chrome('http://127.0.0.1:1', self.root / 'chrome', self.root / 'profile')
        requested = request.call_args.args[2]['capabilities']['alwaysMatch']
        self.assertIs(requested['acceptInsecureCerts'], False)
        self.assertNotIn('--ignore-certificate-errors', requested['goog:chromeOptions']['args'])

    def test_themed_error_and_legacy_error_never_replace_login_or_consent(self):
        self.assertEqual(page_kind({'oidc_error': True}), 'rejected')
        self.assertEqual(page_kind({'text': '{"error":"invalid_request"}'}), 'rejected')
        self.assertEqual(page_kind({'text': 'Unable to continue'}), 'unknown')
        for page in ('login', 'password', 'consent'):
            self.assertEqual(page_kind({page: True, 'oidc_error': True, 'text': 'invalid_request'}), page)

    def test_network_retains_redirect_hops_and_failed_requests(self):
        def event(kind, hop, **extra):
            return {'method': 'network.' + kind, 'params': {'request': {'request': 'same', 'method': 'GET',
                    'url': 'https://op.test/'}, 'redirectCount': hop, 'timestamp': 1000 + hop, **extra}}
        rows = network_rows([event('beforeRequestSent', 0), event('responseCompleted', 0, response={'status': 302}),
                             event('beforeRequestSent', 1), event('fetchError', 1, errorText='TLS rejected')])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['response']['status'], 302)
        self.assertEqual(rows[1]['error'], 'TLS rejected')

    def test_image_upload_enforces_official_decoded_size_limit(self):
        for size in (MAX_SCREENSHOT_BYTES, MAX_SCREENSHOT_BYTES + 1):
            with self.subTest(size=size):
                png = PNG + b'\0' * (size - len(PNG))
                reviewer = object.__new__(Reviewer)
                reviewer.config = {'issuer': 'https://op.test/auth'}
                reviewer.base, reviewer.current, reviewer.output = 'https://suite.test', 'id', self.root
                reviewer.record = {'name': 'oidcc-ensure-registered-redirect-uri', 'visits': [], 'steps': [], 'uploads': []}
                reviewer.save = mock.Mock()
                reviewer.browser = mock.Mock()
                reviewer.browser.script.return_value = {'url': 'https://op.test/auth/oidc/authorize', 'oidc_error': True}
                reviewer.capture = mock.Mock(return_value=({'screenshot': 'frame.png', 'sha256': 'fixture', 'visit': 1}, png))
                reviewer.api = mock.Mock()
                reviewer.api.json.return_value = [{'src': 'ExpectRedirectUriErrorPage', 'upload': 'slot', '_id': 'event'}]
                reviewer.api.request.side_effect = [(204, {}, b''), (200, {}, json.dumps({
                    'img': 'data:image/png;base64,' + base64.b64encode(png).decode()}).encode())]
                url = reviewer.config['issuer'] + '/oidc/authorize?redirect_uri=https://unregistered.test'
                if size > MAX_SCREENSHOT_BYTES:
                    with self.assertRaisesRegex(harness.Blocker, '500 KiB'):
                        reviewer.visit(url)
                    self.assertEqual(reviewer.api.request.call_count, 1)
                    self.assertEqual(reviewer.record['uploads'], [])
                else:
                    reviewer.visit(url)
                    self.assertEqual(len(reviewer.record['uploads']), 1)
                    self.assertEqual(reviewer.api.request.call_args.args[1], b'data:image/png;base64,' + base64.b64encode(png))
                    self.assertTrue((self.root / 'frame.png.upload-response.txt').is_file())

    def test_consent_diagnosis_requires_all_recorded_header_and_status_evidence(self):
        page = {'request': {'method': 'GET', 'url': 'https://op/auth/oidc/continue'},
                'response': {'status': 200, 'headers': [{'name': 'Referrer-Policy', 'value': {'value': 'no-referrer'}}]}}
        post = {'request': {'method': 'POST', 'url': 'https://op/auth/oidc/continue',
                           'headers': [{'name': 'Origin', 'value': {'value': 'null'}}]}, 'response': {'status': 403}}
        self.assertIn('Origin: null', consent_diagnosis([page, post]))
        self.assertIsNone(consent_diagnosis([post]))
        post['response']['status'] = 200
        self.assertIsNone(consent_diagnosis([page, post]))

    def test_signed_png_must_match_original_capture_for_every_review(self):
        (self.root / 'visual').mkdir()
        modules, records, visual = [], [], []
        for i in range(6):
            identifier = str(i)
            modules.append({'id': identifier, 'name': 'oidcc-prompt-login'})
            harness.private_write(self.root / 'visual' / (identifier + '.png'), PNG)
            records.append({'id': identifier, 'uploads': [{'event_id': identifier, 'sha256': harness.digest(self.root / 'visual' / (identifier + '.png'))}]})
            visual.append({'module_id': identifier, 'event_id': identifier, 'capture': identifier + '.png'})
        harness.write_json(self.root / 'browser-evidence.json', records)
        harness.write_json(self.root / 'visual-evidence.json', visual)
        harness.verify_browser_evidence(self.root, {'modules': modules})
        harness.private_write(self.root / 'visual/3.png', PNG + b'changed')
        with self.assertRaisesRegex(harness.Blocker, 'differs'):
            harness.verify_browser_evidence(self.root, {'modules': modules})

    def test_profile_ca_is_scoped_to_a_new_database_with_pinned_trust_encoding(self):
        # The schema test verifies the actual bytes consumed by Chromium; the
        # real E2E additionally rejects an untrusted CA and validates the trusted one.
        profile = self.root / 'profile'
        profile.mkdir()
        ca = self.root / 'ca.pem'
        der = b'certificate fixture'
        ca.write_text(ssl.DER_cert_to_PEM_cert(der))
        trust_ca(profile, ca)
        with closing(sqlite3.connect(profile / 'Default/ServerCertificate')) as database:
            row = database.execute('SELECT * FROM certificates').fetchone()
            self.assertEqual(row, (hashlib.sha256(der).hexdigest(), der, bytes.fromhex('0a020803')))
            self.assertEqual(database.execute("SELECT value FROM meta WHERE key='version'").fetchone(), ('1',))
        with self.assertRaises(FileExistsError):
            trust_ca(profile, ca)  # Never modify an existing user's profile.

    def test_browser_zip_rejects_escape_and_retains_executable_mode(self):
        archive = self.root / 'tool.zip'
        destination = self.root / 'tool'
        destination.mkdir()
        info = zipfile.ZipInfo('tool/bin')
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr(info, '#!/bin/sh\n')
        extract_zip(archive, destination, 'tool', harness.Blocker)
        self.assertEqual((destination / 'bin').stat().st_mode & 0o777, 0o700)
        for name, target in [('tool/../escape', None), ('tool/link', '../escape')]:
            with zipfile.ZipFile(archive, 'w') as z:
                info = zipfile.ZipInfo(name)
                if target:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, target or 'escape')
            with self.assertRaises(harness.Blocker):
                extract_zip(archive, destination, 'tool', harness.Blocker)

    def fixture(self):
        harness.private_write(self.root / 'shot.png', PNG)
        harness.private_write(self.root / 'source.html.txt', '<script>never execute</script>')
        event = {'method': 'network.responseCompleted', 'params': {'timestamp': 1001,
                 'request': {'request': 'request', 'method': 'GET', 'url': 'https://op.test/<script>'},
                 'response': {'status': 400, 'headers': [{'name': 'test', 'value': '</pre><script>bad</script>'}]}}}
        harness.private_write(self.root / 'events.jsonl', json.dumps(event) + '\n')
        record = {'id': 'actual', 'name': 'oidcc-ensure-registered-redirect-uri',
                  'trace': 'events.jsonl', 'capabilities': {'browserVersion': 'pinned', 'acceptInsecureCerts': False},
                  'visits': [{'at': 1000, 'url': 'https://op.test/authorize'}],
                  'steps': [{'at': 1002, 'visit': 1, 'label': 'Redirect rejected', 'url': 'https://op.test/authorize',
                             'screenshot': 'shot.png', 'source': 'source.html.txt', 'sha256': 'hash'}],
                  'uploads': [{'screenshot': 'shot.png', 'source': 'ExpectRedirectUriErrorPage', 'event_id': 'event'}]}
        harness.write_json(self.root / 'browser-evidence.json', [record])
        (self.root / 'exports').mkdir()
        with zipfile.ZipFile(self.root / 'exports/signed.zip', 'w') as archive:
            archive.writestr('result.json', json.dumps({'results': [{'result': 'REVIEW', 'src': 'ExpectRedirectUriErrorPage',
                'msg': 'Review rejection', 'img': 'omitted'}, {'result': 'SUCCESS', 'src': 'Check', 'msg': 'Original check'}]}))
        return record, [{'id': 'actual', 'result': 'REVIEW', 'export': 'signed.zip', 'member': 'result.json'}]

    def test_view_contains_real_images_network_and_original_checks_without_executable_capture(self):
        _, modules = self.fixture()
        views = render_reviews(self.root, modules, '')
        self.assertEqual(views[0]['file'], 'review-actual.html')
        page = (self.root / views[0]['file']).read_text()
        for expected in ('REAL HEADLESS CHROME CAPTURES', 'src="./shot.png"', 'Browser network', 'Suite checks and HTTP', 'REVIEW', 'Original check',
                         'ExpectRedirectUriErrorPage', 'request/response headers', '&lt;script&gt;'):
            self.assertIn(expected, page)
        self.assertNotIn('<script>', page)
        self.assertNotIn('<iframe', page)
        self.assertNotIn('never execute', page)

    def test_view_rejects_image_path_escape(self):
        record, modules = self.fixture()
        record['steps'][0]['screenshot'] = '../outside.png'
        harness.write_json(self.root / 'browser-evidence.json', [record])
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            render_reviews(self.root, modules, '')


if __name__ == '__main__':
    unittest.main()
