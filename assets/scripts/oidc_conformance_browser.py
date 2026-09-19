#!/usr/bin/env python3
"""Real Chrome interactions for the official suite's three visual review cases.

Uses its supported manual-browser URLs and image upload API. Neither test
outcomes nor callback responses are manufactured. All raw evidence is private.
"""

import base64
from contextlib import closing
import json
import os
from pathlib import Path
import hashlib
import sqlite3
import ssl
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from oidc_conformance_browser_tools import CHROME_VERSION
from oidc_conformance import ROOT, Blocker, Browser, digest, ports, private_write, write_json

REVIEW_MODULES = {'oidcc-prompt-login', 'oidcc-max-age-1', 'oidcc-ensure-registered-redirect-uri'}
ELEMENT = 'element-6066-11e4-a52e-4f735466cecf'
# Unmodified suite logging/ImageAPI.java limits decoded uploads to 500 KiB.
MAX_SCREENSHOT_BYTES = 500 * 1024


def chrome_environment():
    """Keep Chromium's temporary Unix sockets short and inside this checkout."""
    temporary = ROOT / 'tmp'
    resolved = temporary.resolve()
    if not temporary.is_dir() or ROOT not in resolved.parents:
        raise Blocker('Chrome temporary directory must remain inside this checkout')
    # Pinned Chromium appends this name to TMPDIR for its singleton socket.
    # Linux sockaddr_un has 108 bytes, including the terminating NUL. Report
    # directories can be much longer; Chrome creates private unique children
    # of this short base and removes them when its sessions close.
    socket_path = temporary / 'org.chromium.Chromium.XXXXXX/SingletonSocket'
    if sys.platform.startswith('linux') and len(os.fsencode(str(socket_path))) >= 108:
        raise Blocker('checkout path is too long for Chrome Unix sockets; use a shorter checkout path')
    return dict(os.environ, TMPDIR=str(temporary))


def page_kind(state):
    """Recognize real forms before either legacy JSON or themed OP errors."""
    for page in ('login', 'password', 'consent'):
        if state.get(page):
            return page
    if state.get('oidc_error') or 'invalid_request' in state.get('text', ''):
        return 'rejected'
    return 'unknown'


def expected_slot(name, visit, page, slots):
    """Never attach first-login or successful-callback images to error slots."""
    source = 'ExpectRedirectUriErrorPage' if name == 'oidcc-ensure-registered-redirect-uri' else 'ExpectSecondLoginPage'
    correct_page = page == 'rejected' if source == 'ExpectRedirectUriErrorPage' else visit == 2 and page == 'login'
    candidates = [s for s in slots if s.get('upload') and s.get('src') == source]
    if not correct_page:
        return None
    if len(candidates) != 1:
        raise Blocker('expected exactly one matching official screenshot placeholder')
    return candidates[0]


def trust_ca(profile, ca):
    """Seed a new private Chrome profile's real custom-CA database offline.

    Schema and proto are pinned to Chromium 153.0.8010.47:
    components/server_certificate_database/server_certificate_database.{cc,proto}
    CertificateMetadata { trust { trust_type: CERTIFICATE_TRUST_TYPE_TRUSTED } }
    does not bypass hostname, chain, expiry or signature validation.
    """
    directory = profile / 'Default'
    directory.mkdir(mode=0o700)
    der = ssl.PEM_cert_to_DER_cert(ca.read_text())
    with closing(sqlite3.connect(directory / 'ServerCertificate')) as database, database:
        database.execute('CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)')
        database.executemany('INSERT INTO meta VALUES(?,?)', [('version', '1'), ('last_compatible_version', '1')])
        database.execute('CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL)')
        database.execute('INSERT INTO certificates VALUES(?,?,?)', (hashlib.sha256(der).hexdigest(), der, bytes.fromhex('0a020803')))



class InteractionBlocked(Blocker):
    """Actual provider UI prevented completion; preserve and cancel this instance."""


class DriverError(Blocker):
    def __init__(self, error):
        self.error = error.get('error')
        super().__init__('WebDriver ' + str(self.error) + ': ' + error.get('message', ''))


class Chrome:
    def __init__(self, endpoint, binary, profile, ca=None):
        profile.mkdir(mode=0o700)
        if ca:
            trust_ca(profile, ca)
        self.endpoint, self.session, self.ws = endpoint, None, None
        self.receiver, self.stream, self.failure = None, None, None
        self.closing = False
        response = self.request('POST', '/session', {'capabilities': {'alwaysMatch': {
            'browserName': 'chrome', 'acceptInsecureCerts': False, 'webSocketUrl': True,
            'goog:chromeOptions': {'binary': str(binary), 'args': ['--headless=new', '--user-data-dir=' + str(profile),
                '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                '--disable-component-update', '--disable-sync', '--no-proxy-server', '--password-store=basic',
                '--use-mock-keychain']}}}})
        self.session = response['sessionId']
        self.capabilities = response['capabilities']
        if self.capabilities.get('browserVersion') != CHROME_VERSION:
            raise Blocker('screenshot browser must match pinned Chrome ' + CHROME_VERSION)
        if self.capabilities.get('acceptInsecureCerts') is not False:
            raise Blocker('browser did not enforce certificate validation')
        self.call('POST', '/timeouts', {'pageLoad': 30000, 'script': 10000, 'implicit': 0})
        self.call('POST', '/window/rect', {'width': 1280, 'height': 900})

    def request(self, method, path, data=None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(self.endpoint + path, data=body, method=method,
                                         headers={'Content-Type': 'application/json'})
        try:
            response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            value = json.load(response).get('value')
            if response.status >= 400:
                raise DriverError(value)
            return value

    def call(self, method, path, data=None):
        return self.request(method, '/session/' + self.session + path, data)

    def script(self, script):
        return self.call('POST', '/execute/sync', {'script': script, 'args': []})

    def element(self, selector):
        return self.call('POST', '/element', {'using': 'css selector', 'value': selector})[ELEMENT]

    def type(self, selector, value):
        element = self.element(selector)
        self.call('POST', '/element/' + element + '/value', {'text': value})

    def click(self, selector):
        document = self.element('html')
        self.call('POST', '/element/' + self.element(selector) + '/click', {})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                changed = self.element('html') != document
                if changed and self.script("return document.readyState") == 'complete':
                    return
            except DriverError as error:
                if error.error not in ('no such element', 'stale element reference'):
                    raise
            time.sleep(.1)
        raise Blocker('form submission did not finish navigation; no second submission attempted')

    def trace(self, path):
        import websocket  # Only the isolated conformance venv needs this package.
        self.stream = path.open('x', encoding='utf-8')
        self.ws = websocket.create_connection(self.capabilities['webSocketUrl'], timeout=1,
                                              suppress_origin=True, http_no_proxy=['127.0.0.1', 'localhost'])
        self.ws.send(json.dumps({'id': 1, 'method': 'session.subscribe', 'params': {'events': [
            'network.beforeRequestSent', 'network.responseStarted', 'network.responseCompleted',
            'network.fetchError', 'log.entryAdded', 'browsingContext.navigationStarted',
            'browsingContext.load']}}))
        acknowledgement = json.loads(self.ws.recv())
        if acknowledgement.get('type') != 'success':
            raise Blocker('could not subscribe to real browser network events')

        def receive():
            try:
                while not self.closing:
                    try:
                        data = self.ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    if not data:
                        if not self.closing:
                            raise Blocker('browser event connection closed unexpectedly')
                        break
                    event = json.loads(data)
                    event['recorded_at'] = time.time_ns() // 1000000
                    self.stream.write(json.dumps(event) + '\n')
                    self.stream.flush()
            except Exception:
                if not self.closing:
                    self.failure = traceback.format_exc()
        self.receiver = threading.Thread(target=receive, daemon=True)
        self.receiver.start()

    def close(self):
        self.closing = True
        if self.ws:
            self.ws.close()
        if self.receiver:
            self.receiver.join(timeout=5)
        if self.stream:
            self.stream.close()
        if self.session:
            self.call('DELETE', '', None)
            self.session = None


class Reviewer:
    def __init__(self, config):
        self.output = Path(config['output'])
        self.config = config
        self.api, self.base = Browser(Path(config['ca'])), config['base']
        self.browser, self.driver_process = None, None
        self.current, self.finished = None, set()
        self.record = None
        self.records = []
        self.binary = Path(config['chrome'])
        self.endpoint = 'http://127.0.0.1:' + str(ports(1)[0])

    def start(self):
        environment = chrome_environment()
        with (self.output / 'chromedriver.log').open('xb') as log:
            self.driver_process = subprocess.Popen([self.config['chromedriver'], '--port=' + self.endpoint.rsplit(':', 1)[1]],
                                                   cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 20
        while True:
            try:
                with urllib.request.urlopen(self.endpoint + '/status', timeout=1):
                    break
            except urllib.error.URLError:
                if time.monotonic() >= deadline or self.driver_process.poll() is not None:
                    raise Blocker('chromedriver did not become ready; see private chromedriver.log')
                time.sleep(.1)
        # A new profile without the test CA must reject the deployment.
        self.browser = Chrome(self.endpoint, self.binary, self.output / 'runtime/chrome-untrusted')
        probe_url = self.config['issuer'] + '/.well-known/openid-configuration'
        negative = self.browser.call('POST', '/goog/cdp/execute', {'cmd': 'Page.navigate', 'params': {'url': probe_url}})
        if negative.get('errorText') != 'net::ERR_CERT_AUTHORITY_INVALID':
            raise Blocker('Chrome negative CA trust control did not reject the test CA')
        self.browser.close()
        self.browser = None
        self.browser = Chrome(self.endpoint, self.binary, self.output / 'runtime/chrome-trusted', Path(self.config['ca']))
        self.browser.call('POST', '/url', {'url': self.config['issuer'] + '/.well-known/openid-configuration'})
        if self.config['issuer'] not in self.browser.call('GET', '/source'):
            raise Blocker('trusted Chrome did not receive Caddy discovery')
        write_json(self.output / 'browser-tls.json', {'untrusted_ca_rejected': True, 'trusted_https': True,
                   'negative_navigation': negative, 'acceptInsecureCerts': False, 'ca_sha256': digest(Path(self.config['ca'])),
                   'temporary_directory': environment['TMPDIR'],
                   'capabilities': self.browser.capabilities, 'chromedriver_pid': self.driver_process.pid,
                   'binary_sha256': digest(self.binary), 'trust': 'private profile ServerCertificate database (pinned Chromium schema v1)'})
        self.browser.close()
        self.browser = None
        private_write(self.output / 'review-browser.ready', 'ready\n')

    def save(self):
        write_json(self.output / 'browser-evidence.json', self.records)

    def begin(self, info):
        if self.browser:
            self.end()
        self.current = info['id']
        directory = self.output / 'browser' / self.current
        directory.mkdir(parents=True, mode=0o700)
        self.browser = Chrome(self.endpoint, self.binary, self.output / 'runtime' / ('chrome-' + self.current), Path(self.config['ca']))
        self.browser.trace(directory / 'events.jsonl')
        self.record = {'id': self.current, 'name': info['name'], 'visits': [], 'steps': [], 'uploads': [],
                       'capabilities': self.browser.capabilities, 'trace': str(directory.relative_to(self.output) / 'events.jsonl')}
        self.records.append(self.record)
        self.save()

    def end(self):
        self.browser.close()
        if self.browser.failure:
            private_write(self.output / 'browser-trace-error.log', self.browser.failure)
            raise Blocker('browser network evidence failed; see private browser-trace-error.log')
        self.browser = None
        self.finished.add(self.current)
        self.current = None
        self.save()

    def capture(self, label, page):
        sequence = len(self.record['steps']) + 1
        prefix = 'browser/' + self.current + '/' + str(sequence).zfill(2)
        png = base64.b64decode(self.browser.call('GET', '/screenshot'), validate=True)
        if not png.startswith(b'\x89PNG\r\n\x1a\n'):
            raise Blocker('WebDriver screenshot was not PNG')
        private_write(self.output / (prefix + '.png'), png)
        private_write(self.output / (prefix + '.html.txt'), self.browser.call('GET', '/source'))
        step = {'at': time.time_ns() // 1000000, 'label': label, 'page': page, 'visit': len(self.record['visits']),
                'url': self.browser.call('GET', '/url'), 'screenshot': prefix + '.png', 'source': prefix + '.html.txt',
                'sha256': digest(self.output / (prefix + '.png'))}
        self.record['steps'].append(step)
        self.save()
        return step, png

    def visit(self, url):
        issuer = self.config['issuer']
        if not url.startswith(issuer + '/oidc/authorize?'):
            raise Blocker('unexpected official review authorization URL')
        self.record['visits'].append({'url': url, 'at': time.time_ns() // 1000000})
        self.save()
        self.browser.call('POST', '/url', {'url': url})
        response = self.api.request(self.base + '/api/runner/browser/' + self.current + '/visit?' +
                                    urllib.parse.urlencode({'url': url}), b'')
        if response[0] != 204:
            raise Blocker('suite did not acknowledge the real browser navigation')
        for _ in range(12):
            state = self.browser.script("""return {url:location.href, text:document.body.innerText,
                login:!!document.querySelector('input[name=username]'),
                password:!!document.querySelector('input[name=secret]'),
                consent:!!document.querySelector('button[name=decision][value=allow]'),
                oidc_error:document.body.classList.contains('oidc-page') &&
                    document.querySelector('#oidc-title')?.textContent.trim()==='Unable to continue' &&
                    document.querySelector('[role=alert]')?.textContent.includes('This sign-in request is invalid or has expired.') &&
                    !document.querySelector('form')};""")
            if state['url'].startswith(self.base + '/test/') and '/callback' in state['url']:
                self.capture('Suite received the real browser callback', 'callback')
                return
            if not state['url'].startswith(issuer + '/'):
                raise Blocker('review browser left the configured OP and suite callback')
            page = page_kind(state)
            labels = {'login': 'Fresh login required', 'password': 'Password challenge before submission',
                      'consent': 'Explicit consent before Allow', 'rejected': 'Provider rejected the sign-in request', 'unknown': 'Unexpected page'}
            redirect_error = (self.record['name'] == 'oidcc-ensure-registered-redirect-uri'
                              and urllib.parse.urlsplit(state['url']).path == urllib.parse.urlsplit(issuer).path + '/oidc/authorize')
            if redirect_error:
                labels['rejected'] = 'Unregistered redirect rejected on the OP'
            step, png = self.capture(labels[page], page)
            slots = self.api.json(self.base + '/api/log/' + self.current + '/images')
            slot_page = 'unknown' if self.record['name'] == 'oidcc-ensure-registered-redirect-uri' and not redirect_error else page
            slot = expected_slot(self.record['name'], len(self.record['visits']), slot_page, slots)
            if slot:
                if len(png) > MAX_SCREENSHOT_BYTES:
                    raise Blocker('real Chrome screenshot exceeds the official 500 KiB upload limit; use a smaller browser viewport')
                code, _, body = self.api.request(self.base + '/api/log/' + self.current + '/images/' +
                    urllib.parse.quote(slot['upload'], safe=''), b'data:image/png;base64,' + base64.b64encode(png),
                    {'Content-Type': 'text/plain'})
                private_write(self.output / (step['screenshot'] + '.upload-response.txt'), body)
                if code != 200 or not body or json.loads(body).get('img') != 'data:image/png;base64,' + base64.b64encode(png).decode():
                    raise Blocker('official screenshot upload was not acknowledged (HTTP ' + str(code) + '); inspect the private upload response')
                self.record['uploads'].append({'placeholder': slot['upload'], 'source': slot['src'],
                    'event_id': slot['_id'], 'screenshot': step['screenshot'], 'sha256': step['sha256'], 'visit': step['visit']})
                self.save()
            if page == 'login':
                self.browser.type('input[name=username]', 'conformance')
                self.browser.click('.app-btn-pri')
            elif page == 'password':
                self.browser.type('input[name=secret]', self.config['password'])
                self.browser.click('[name=submit]')
            elif page == 'consent':
                self.browser.click('button[name=decision][value=allow]')
            elif page == 'rejected' and slot:
                return
            else:
                raise InteractionBlocked('provider displayed ' + page + ' instead of the expected next step after ' + str(len(self.record['steps'])) + ' captures')
        raise Blocker('review browser exceeded interaction bound')

    def tick(self):
        running = self.api.json(self.base + '/api/runner/running')
        for identifier in running:
            if identifier in self.finished:
                continue
            info = self.api.json(self.base + '/api/runner/' + identifier)
            if info['name'] not in REVIEW_MODULES:
                continue
            if info.get('status') in ('FINISHED', 'INTERRUPTED'):
                if self.current == identifier:
                    self.end()
                self.finished.add(identifier)
                continue
            urls = info.get('browser', {}).get('urls', [])
            if urls:
                if self.current != identifier:
                    self.begin(info)
                for url in urls:
                    try:
                        self.visit(url)
                    except InteractionBlocked as error:
                        # The official cancel API records an interruption. It
                        # lets independent modules proceed without fabricating
                        # a callback or filling an unrelated image slot.
                        self.record['blocker'] = str(error)
                        code, _, _ = self.api.request(self.base + '/api/runner/' + identifier, method='DELETE')
                        self.record['cancel_http_status'] = code
                        self.save()
                        if code != 200:
                            raise Blocker('could not cancel blocked official module') from error
                        self.end()
                        break
        if self.current and self.current not in running:
            self.end()

    def close(self):
        try:
            if self.browser:
                self.browser.close()
        finally:
            if self.driver_process:
                self.driver_process.terminate()
                try:
                    self.driver_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.driver_process.kill()
                    self.driver_process.wait(timeout=5)
                write_json(self.output / 'browser-process.json', {'pid': self.driver_process.pid,
                           'exit_code': self.driver_process.returncode, 'reaped': True})



def main():
    os.umask(0o077)
    config = json.loads(Path(sys.argv[1]).read_text())
    reviewer = Reviewer(config)
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        reviewer.start()
        while not (reviewer.output / 'review-browser.stop').exists():
            reviewer.tick()
            time.sleep(.2)
        reviewer.tick()
        if reviewer.browser:
            reviewer.end()
        return 0
    except (Exception, KeyboardInterrupt):
        private_write(reviewer.output / 'review-browser-error.log', traceback.format_exc())
        return 1
    finally:
        reviewer.close()


if __name__ == '__main__':
    sys.exit(main())
