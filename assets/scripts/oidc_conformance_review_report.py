"""Offline screenshot timeline and developer-tools view of original evidence."""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import PurePosixPath
from urllib.parse import quote, urlsplit
import zipfile


def safe_path(output, name):
    name = str(name)
    path = PurePosixPath(name)
    if (path.is_absolute() or '..' in path.parts or '\\' in name
            or not (output / name).resolve().is_relative_to(output.resolve())):
        raise ValueError('unsafe browser evidence path')
    return output / name


def link(output, name, label, download=True):
    if not safe_path(output, name).is_file():
        return escape(label) + ' (not recorded)'
    return '<a href="./' + quote(str(name), safe='/') + '"' + (' download' if download else '') + '>' + escape(label) + '</a>'


def pretty(data):
    return '<pre>' + escape(json.dumps(data, indent=2, ensure_ascii=False)) + '</pre>'


def timestamp(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec='milliseconds')


def display_url(url):
    parsed = urlsplit(url)
    if parsed.scheme in ('http', 'https'):
        return parsed.path
    return parsed.scheme + ': embedded/local resource'  # Raw URI remains in event details.


def network_rows(events):
    """Group BiDi events by request and redirect hop; never collapse redirects."""
    requests = {}
    for event in events:
        method, data = event.get('method', ''), event.get('params', {})
        if not method.startswith('network.'):
            continue
        request = data.get('request', {})
        key = request.get('request'), data.get('redirectCount', 0)
        entry = requests.setdefault(key, {'at': data.get('timestamp', event.get('recorded_at', 0)),
                                         'request': request, 'events': []})
        entry['events'].append(event)
        if data.get('response'):
            entry['response'] = data['response']
        if method == 'network.fetchError':
            entry['error'] = data.get('errorText', 'fetch failed')
    return sorted(requests.values(), key=lambda r: r['at'])


def header_value(header):
    value = header.get('value', '')
    return value.get('value', '') if isinstance(value, dict) else str(value)


def header_values(headers, name):
    return [header_value(h) for h in headers if h.get('name', '').lower() == name.lower()]


def consent_diagnosis(rows):
    pages = [r for r in rows if r['request'].get('method') == 'GET'
             and urlsplit(r['request'].get('url', '')).path.endswith('/oidc/continue')
             and 'no-referrer' in header_values(r.get('response', {}).get('headers', []), 'referrer-policy')]
    rejected = [r for r in rows if r['request'].get('method') == 'POST'
                and urlsplit(r['request'].get('url', '')).path.endswith('/oidc/continue')
                and 'null' in header_values(r['request'].get('headers', []), 'origin')
                and r.get('response', {}).get('status') == 403]
    if pages and rejected:
        return ('The recorded consent page sets Referrer-Policy: no-referrer. Chrome sends Origin: null when Allow submits the form, '
                'and the provider responds HTTP 403 invalid_request. This matches the go-authcrunch consent origin-check conflict: '
                'the upstream page policy removes the origin its own handler requires. Authentication reached consent, but did not '
                'reach the first callback or the second login. Fix the upstream page policy while retaining same-origin and CSRF checks; '
                'do not approve this as successful reauthentication.')
    return None


def headers_view(headers):
    return '<pre>' + escape('\n'.join(h.get('name', '') + ': ' + str(header_value(h)) for h in headers)) + '</pre>'


GUIDANCE = {
    'oidcc-prompt-login': ('Confirm that the second authorization contains prompt=login and returns to a fresh login/password challenge. '
        'The same browser profile and cookies are retained between authorizations. Compare both login sequences and the suite’s auth_time check.'),
    'oidcc-max-age-1': ('Confirm max_age=1 in the second authorization after the suite’s wait, and a fresh login/password challenge. '
        'The same browser profile and cookies are retained. Compare the suite’s auth_time presence, recency and second-login checks.'),
    'oidcc-ensure-registered-redirect-uri': ('Confirm the authorization request uses an unregistered redirect URI, the browser remains on the provider’s '
        'authorization endpoint, and the screenshot shows invalid_request. The browser must not send an authorization response to that redirect URI.'),
}


def render_reviews(output, modules, style):
    path = output / 'browser-evidence.json'
    if not path.is_file():
        return []
    records = json.loads(path.read_text())
    verification = output / 'browser-export-verification.json'
    verified = json.loads(verification.read_text()) if verification.is_file() else []
    rendered = []
    for record in records:
        module = next((m for m in modules if m.get('id') == record['id']), {})
        identifier = record['id']
        verified_ids = {v['event_id'] for v in verified if v['module_id'] == identifier}
        filename = 'review-' + identifier + '.html'
        safe_path(output, filename)
        events_path = safe_path(output, record['trace'])
        events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.is_file() else []
        suite_events = []
        if module.get('export'):
            with zipfile.ZipFile(safe_path(output, 'exports/' + module['export'])) as archive:
                suite_events = json.loads(archive.read(module['member']))['results']
        rows = network_rows(events)
        diagnosis = consent_diagnosis(rows)
        start = min([r['at'] for r in rows] + [s['at'] for s in record['steps']] +
                    [v['at'] for v in record['visits']])
        e = escape
        parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
            '<title>Visual review · ' + e(record['name']) + '</title><style>' + style + '''
            .filmstrip{display:flex;overflow-x:auto;gap:1rem;padding-bottom:1rem}.filmstrip a{flex:0 0 220px}
            .filmstrip img{width:220px;border:1px solid #ccd5e0}.review-grid{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:1.2rem}
            .review-grid>div{min-width:0}:root{overflow-wrap:anywhere}
            .shot{width:100%;border:1px solid #ccd5e0}.step{scroll-margin-top:1rem} .url{word-break:break-all}
            .request summary{font:13px/1.6 ui-monospace,monospace;display:grid;grid-template-columns:6em 5em 5em 1fr;gap:.5rem}
            .request{border-bottom:1px solid #d6dfeb;padding:.35rem} .network{max-height:650px;overflow:auto}
            .request:nth-child(even){background:#f7f9fc}.time{font-variant-numeric:tabular-nums}.target{border-left:5px solid #ad6800}
            @media(max-width:900px){.review-grid{grid-template-columns:1fr}}
            </style></head><body><main><header><a href="./index.html#visual">← Conformance report</a>''',
            '<div class="eyebrow">REAL HEADLESS CHROME CAPTURES · TEST EVIDENCE</div><h1>' + e(record['name']) + '</h1>',
            '<p>Official outcome: <strong>' + e(module.get('outcome', module.get('result', 'NOT COLLECTED'))) + '</strong> · instance ' + e(identifier) + '</p>',
            '<p>Response mode: ' + e(str((module.get('variant') or {}).get('response_mode', 'not collected'))) + '</p>',
            '<p>' + e(GUIDANCE.get(record['name'], 'Review the original suite conditions.')) + '</p>',
            '<p class="notice">Screenshots document what was displayed; they do not approve a REVIEW result. This view includes full URLs, '
            'headers, cookies and tokens from the disposable test deployment. No certification materials were submitted.</p>',
            '<nav><a href="#timeline">Screenshot timeline</a><a href="#network">Browser network</a><a href="#suite">Suite checks and HTTP</a><a href="#console">Console</a></nav></header>',
            '<section><h2>Evidence provenance</h2><p>These PNGs came directly from WebDriver during real navigation, before submitting the displayed forms. '
            'No page was reconstructed. The browser enforced TLS validation. One new profile per module; the first and second authorization share it.</p>',
            '<p>Browser: ' + e(str(record['capabilities'].get('browserVersion'))) + ' · acceptInsecureCerts: ' + e(str(record['capabilities'].get('acceptInsecureCerts'))) + '</p>',
            '<p>' + ' · '.join([link(output, record['trace'], 'Original WebDriver BiDi events'), link(output, 'browser-evidence.json', 'Screenshot manifest'),
                              link(output, 'browser-tls.json', 'Browser trust controls')] +
                              ([link(output, 'exports/' + module['export'], 'Original signed suite export')] if module.get('export') else [])) + '</p>',
            '<p>Browser network events cover front-channel traffic. Token and UserInfo calls originate from the Java suite and appear under Suite checks and HTTP. '
            'HTTP bodies are available there; BiDi records headers, status and timing without inventing missing browser response bodies.</p></section>',
            '<section id="timeline"><h2>Screenshot timeline</h2><div class="filmstrip">']
        for i, step in enumerate(record['steps'], 1):
            safe_path(output, step['screenshot'])
            parts.append('<a href="#step-' + str(i) + '"><img alt="Step ' + str(i) + ' screenshot" src="./' + quote(step['screenshot'], safe='/') + '"><br>' +
                         str(i) + ' · Authorization ' + str(step['visit']) + ' · ' + e(step['label']) + '</a>')
        parts.append('</div>')
        if record.get('blocker'):
            parts.append('<p class="notice"><strong>Interaction blocked:</strong> ' + e(record['blocker']) + ' The harness requested official cancellation of this instance. No callback or review image was fabricated.</p>')
        parts.append('</section>')
        if diagnosis:
            parts.append('<section><h2>What blocked this interaction</h2><p class="notice">' + e(diagnosis) + '</p></section>')
        uploads = {u['screenshot']: u for u in record['uploads']}
        for i, step in enumerate(record['steps'], 1):
            uploaded = uploads.get(step['screenshot'])
            parts.append('<section class="step' + (' target' if uploaded else '') + '" id="step-' + str(i) + '"><h2>' + str(i) + ' · ' + e(step['label']) + '</h2><div class="review-grid"><div>')
            parts.append('<a href="./' + quote(step['screenshot'], safe='/') + '"><img class="shot" alt="' + e(step['label']) + '" src="./' + quote(step['screenshot'], safe='/') + '"></a></div><div>')
            parts.append('<p>Authorization ' + str(step['visit']) + ' · <span class="time">+' + f"{(step['at'] - start) / 1000:.3f}" + ' s</span></p><p>' + e(timestamp(step['at'])) + '</p><p class="url">' + e(step['url']) + '</p>')
            if uploaded:
                parts.append('<p class="notice"><strong>Submitted to the exact official image slot:</strong> ' + e(uploaded['source']) +
                             '<br>Event ' + e(uploaded['event_id']) + '<br>' + ('The PNG was verified byte-for-byte in the signed export.' if uploaded['event_id'] in verified_ids else 'Signed-export PNG verification is not recorded; inspect the run error.') + ' REVIEW remains outstanding.</p>')
            parts.append('<p>' + link(output, step['source'], 'Original HTML source (text)') + '</p><details><summary>Screenshot SHA-256</summary>' + pretty(step['sha256']) + '</details>')
            previous = record['steps'][i-2]['at'] if i > 1 else start
            recent = [r for r in rows if previous <= r['at'] <= step['at']]
            parts.append('<h3>Requests since the previous screenshot</h3><ul>')
            for r in recent:
                request = r['request']
                status = r.get('response', {}).get('status', r.get('error', 'pending'))
                parts.append('<li><code>' + e(str(status)) + ' ' + e(request.get('method', '')) + '</code> ' +
                             e(display_url(request.get('url', ''))) + '</li>')
            parts.append('</ul></div></div></section>')
        parts.append('<section id="network"><h2>Browser network</h2><p>Expand a request for its original events and request/response headers. Redirect hops remain separate. '
                     'Times are relative to the first recorded action; all raw timestamps are retained.</p><div class="network">')
        for r in rows:
            request = r['request']
            response = r.get('response', {})
            parts.append('<details class="request"><summary><span class="time">+' + f"{(r['at']-start)/1000:.3f}s" + '</span><span>' + e(request.get('method', '')) + '</span><span>' +
                         e(str(response.get('status', r.get('error', 'pending')))) + '</span><span class="url">' + e(display_url(request.get('url', ''))) + '</span></summary><p class="url">' + e(request.get('url', '')) + '</p><div class="review-grid"><div><h3>Request headers</h3>' +
                         headers_view(request.get('headers', [])) + '</div><div><h3>Response headers</h3>' + headers_view(response.get('headers', [])) +
                         '</div></div><details><summary>Original events, timing and metadata</summary>' + pretty(r['events']) + '</details></details>')
        parts.append('</div></section><section id="suite"><h2>Suite checks and HTTP</h2><p>Original signed-log order, including successful checks, non-pass conditions and back-channel traffic. '
                     'Open an entry to see its complete recorded fields. Image bytes are linked above.</p>')
        for event in suite_events:
            if not (event.get('result') or event.get('http')):
                continue
            fields = {k: v for k, v in event.items() if k not in ('img', 'page_source')}
            parts.append('<details><summary>' + e(str(event.get('result', 'HTTP'))) + ' · ' + e(event.get('src', '')) + ' · ' + e(event.get('msg', '')) + '</summary>' + pretty(fields) + '</details>')
        parts.append('</section><section id="console"><h2>Browser console</h2>')
        console = [event for event in events if event.get('method') == 'log.entryAdded']
        parts.append(pretty(console) if console else '<p>No console entries were recorded.</p>')
        parts.append('</section></main></body></html>')
        target = output / filename
        target.write_text('\n'.join(parts))
        target.chmod(0o600)
        rendered.append({'id': identifier, 'name': record['name'], 'file': filename, 'uploads': record['uploads'], 'mode': (module.get('variant') or {}).get('response_mode', 'unknown')})
    return rendered
