"""Offline, private HTML navigation for one recorded Caddy conformance run."""

from collections import Counter, defaultdict
from html import escape
import json
from pathlib import PurePosixPath
from urllib.parse import quote

from oidc_conformance_review_report import render_reviews


OUTCOMES = {
    "PASSED": "The suite assertions passed for this module instance.",
    "WARNING": "The suite recorded a warning. Read the conditions before assessing its impact.",
    "SKIPPED": "The suite did not exercise this capability; this is not a passing test.",
    "REVIEW": "Human review of the captured behavior remains outstanding.",
    "FAILED": "A suite assertion failed and needs investigation.",
    "INTERRUPTED": "Execution was interrupted; this instance is incomplete.",
    "UNKNOWN": "No recognized outcome is recorded; do not infer a pass.",
}

# Context for the pinned plans, never replacements for the actual conditions.
CONTEXT = {
    ("oidcc-scope-profile", "WARNING"): "Check the recorded condition and explicit identity profile attributes; missing user data must not be fabricated.",
    ("oidcc-ensure-request-with-acr-values-succeeds", "WARNING"): "Check configured authentication-context mappings, discovery and the returned acr claim; amr is separate.",
    ("oidcc-claims-essential", "WARNING"): "Check discovery and the requested individual claims against identity data and consented permissions.",
    ("oidcc-discovery-endpoint-verification", "WARNING"): "Read the discovery warning and recorded library version. v1.2.6 adds RS256 Request Object support, which is separate from ID-token signing.",
    ("oidcc-scope-address", "SKIPPED"): "Check advertised address support and client scope registration for this deployment.",
    ("oidcc-scope-phone", "SKIPPED"): "Check advertised phone support and client scope registration for this deployment.",
    ("oidcc-scope-all", "SKIPPED"): "Check which optional scopes this module requires against discovery and registration.",
    ("oidcc-refresh-token", "SKIPPED"): "Check the recorded OIDC refresh capability and registration. v1.2.6 supports this grant; portal refresh remains a separate protocol.",
    ("oidcc-prompt-login", "REVIEW"): "Review the actual repeated-login page for prompt=login.",
    ("oidcc-max-age-1", "REVIEW"): "Review reauthentication after the suite's max_age wait.",
    ("oidcc-ensure-registered-redirect-uri", "REVIEW"): "Review rejection of the unregistered redirect URI.",
    ("oidcc-ensure-request-object-with-redirect-uri", "REVIEW"): "This module accepts the registered callback inside the Request Object or an actual redirect-error page. A login-page capture does not satisfy its error-page slot. Inspect both evidence and callback validation.",
    ("oidcc-ensure-request-object-with-redirect-uri", "PASSED"): "The suite accepted the real callback using the redirect URI inside the Request Object. Its optional error-page placeholder can remain unfilled; the original placeholder REVIEW event is retained and is not the module outcome.",
}

DESCRIPTIONS = {
    "execution.json": "Run state, original runner exit, interruption and harness errors",
    "summary.json": "Every module instance, outcome and non-pass condition",
    "runner.log": "Original official runner output",
    "runner-command.json": "Exact official runner invocation",
    "runner-working-directory.json": "Working directory for relative runner config and export paths",
    "candidate.json": "Caddy candidate and dependency versions, hashes and origins",
    "source-manifest.json": "Hashes of tracked and untracked candidate sources",
    "source.tar.gz": "Exact tracked and untracked source snapshot used for this run",
    "candidate.patch": "Tracked source changes relative to HEAD",
    "build.txt": "Go metadata embedded in the actual Caddy binary",
    "suite-build.properties": "Suite jar's embedded clean Git revision",
    "suite-server.json": "Running suite version and metadata",
    "tools.json": "JDK, MongoDB, Python dependencies and suite jar hash",
    "prerequisites.json": "Pinned tool distribution checksums and suite build command",
    "discovery.json": "Discovery served by this Caddy deployment",
    "deployment.redacted.json": "Redacted adapted Caddy deployment",
    "Caddyfile.redacted": "Redacted original deployment source",
    "tls.json": "Trusted HTTPS preflight and negative CA trust control",
    "op-jwks.json": "Provider's public OIDC signing keys",
    "suite-jwks.json": "Suite's public signed-export verification key",
    "visual-evidence.json": "Signed screenshot/page-source captures and unfilled review placeholders",
    "browser-evidence.json": "Real browser screenshot timeline and exact image-slot uploads",
    "browser-tls.json": "Real Chrome TLS validation and negative CA trust control",

    "local-e2e.json": "Real password, consent, code exchange and replay checks",
    "unit-tests.log": "Isolated conformance harness unit results",
    "processes.json": "Owned process exit and cleanup records",
    "evidence-sha256.json": "SHA-256 inventory, including this report",
}

STYLE = """
:root { color-scheme: light; font: 16px/1.55 system-ui, sans-serif; color: #182537; background: #f2f5f9; overflow-wrap: anywhere; }
body { margin: 0; } main { max-width: 1180px; margin: auto; padding: 2rem 1.25rem 4rem; }
header, section { background: white; border: 1px solid #d6dfeb; border-radius: 12px; padding: 1.4rem; margin-bottom: 1.25rem; }
h1, h2, h3 { line-height: 1.25; } h1 { margin: .4rem 0; } h2 { margin-top: 0; }
a { color: #07549a; text-underline-offset: .15em; } code, pre { font-size: .88em; overflow-wrap: anywhere; }
pre { white-space: pre-wrap; background: #f2f5f9; padding: .8rem; border-radius: 6px; }
nav { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 1rem; } .muted { color: #4b5a6d; }
.notice { border-left: 4px solid #ad6800; padding: .5rem 1rem; background: #fff8e6; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: .75rem; }
.card { padding: 1rem; border: 1px solid #d6dfeb; border-radius: 8px; } .number { display: block; font-size: 2rem; font-weight: 700; }
.badge { font: 700 .8rem system-ui, sans-serif; border-radius: 5px; padding: .25rem .4rem; display: inline-block; background: #e8edf3; }
.passed { color: #16552e; background: #e4f4e9; } .warning, .review { color: #704000; background: #fff1cc; }
.failed, .interrupted { color: #942525; background: #fde8e8; } .scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; } th, td { border-bottom: 1px solid #dde4ed; padding: .65rem; text-align: left; vertical-align: top; }
th { background: #f2f5f9; } td:first-child { overflow-wrap: anywhere; } .module { min-width: 230px; }
summary { cursor: pointer; font-weight: 600; } details { margin: .6rem 0; } dl { display: grid; grid-template-columns: minmax(120px, 190px) minmax(0, 1fr); gap: .4rem 1rem; }
dt { font-weight: 600; } dd { margin: 0; overflow-wrap: anywhere; } .eyebrow { font-weight: 700; color: #4b5a6d; }
@media (max-width: 600px) { main { padding: .7rem; } header, section { padding: 1rem; } dl { display: block; } dd { margin-bottom: .7rem; } }
@media print { body { background: white; } header, section { break-inside: avoid; } }
"""


def text(value):
    return escape(str(value), quote=True)


def badge(outcome):
    style = outcome.lower() if outcome in OUTCOMES else "unknown"
    return f'<span class="badge {style}">{text(outcome)}</span>'


def render_report(output):
    """Render recorded evidence only; never change a suite result or run state."""
    issues = []

    def read(name, default):
        path = output / name
        if not path.is_file():
            return default
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as error:
            issues.append(f"Cannot read {name}: {type(error).__name__}. Inspect the raw artifact.")
            return default

    def link(name, label=None, download=True):
        # Treat filenames in suite evidence as untrusted. Never link outside
        # this bundle, execute captured HTML, or load remote resources.
        name = str(name)
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or "\\" in name
                or not (output / name).resolve().is_relative_to(output.resolve())):
            return text(label or name) + " (unsafe evidence path)"
        if not (output / name).is_file() and name != "evidence-sha256.json":
            return text(label or name) + " (not recorded)"
        return f'<a href="./{quote(name, safe="/")}"{ " download" if download else ""}>{text(label or name)}</a>'

    status = read("execution.json", {})
    summary = read("summary.json", {})
    candidate = read("candidate.json", {})
    visual = read("visual-evidence.json", [])
    modules = summary.get("modules", [])
    reviews = render_reviews(output, modules, STYLE)
    counts = Counter(m.get("outcome", m.get("result", "UNKNOWN")) for m in modules)
    columns = list(OUTCOMES) + sorted(set(counts) - set(OUTCOMES))
    plans, membership, descriptions = [], {}, {}
    for path in sorted(output.glob("plan-*.json")):
        plan = read(path.name, {})
        if not plan:
            continue
        plans.append((path.name, plan))
        for module in plan.get("modules", []):
            for identifier in module.get("instances", []):
                membership[identifier] = plan.get("planName", "Unknown plan")
                descriptions[identifier] = module.get("testSummary", "")

    complete = (len(modules) == 71 and summary.get("plans") == 3
                and len(plans) == 3 and not summary.get("not_run")
                and {m.get("id") for m in modules} == set(membership)
                and all(m.get("status") == "FINISHED" for m in modules))
    all_passed = (complete and counts == {"PASSED": 71} and status.get("runner_exit_code") == 0
                  and status.get("state") == "RUNNER_FINISHED" and status.get("all_passed") is True
                  and not any(status.get(k) for k in ("interruption", "blocker", "report_error")))
    if status.get("blocker") or status.get("interruption") or status.get("state") == "EVIDENCE_ERROR":
        headline = "Run needs investigation"
    elif all_passed:
        headline = "All recorded modules passed"
    elif status.get("local_only"):
        headline = "Local preflight only — no official plan result"
    elif counts.get("INTERRUPTED"):
        headline = "Plans contain interrupted modules"
    elif not complete:
        headline = "Official evidence is incomplete"
    else:
        headline = "Plans completed with non-pass results"

    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'">',
             '<title>Caddy OIDC conformance report</title><style>' + STYLE + '</style></head><body><main>',
             '<header><div class="eyebrow">CADDY · OPENID FOUNDATION SUITE · PRIVATE REHEARSAL</div>',
             '<h1>OIDC conformance report</h1><p>' + text(headline) + '</p>',
             '<p class="notice">This bundle contains private credentials, logs, and identity data. Keep it private. '
             'This rehearsal is not OpenID certification; no materials were submitted.</p>',
             '<nav aria-label="Report sections">' + ''.join(f'<a href="#{key}">{label}</a>' for key, label in (
                 ('overview', 'Run overview'), ('plans', 'Plans'), ('modules', 'Every module'),
                 ('visual', 'Visual review'), ('provenance', 'Provenance'), ('artifacts', 'All artifacts'))) + '</nav></header>',
             '<section id="overview"><h2>Run overview</h2><dl>']
    facts = {"Run state": status.get("state", "Not recorded"),
             "Original runner exit": status.get("runner_exit_code") if status.get("runner_exit_code") is not None else "Not started / not recorded",
             "Started (UTC)": status.get("started_at", "Not recorded"),
             "Finished (UTC)": status.get("finished_at", "Not recorded"),
             "Collected instances": f"{len(modules)} / 71 expected across 3 plans",
             "Verified export signatures": summary.get("verified_signatures", "Not recorded")}
    parts.extend(f'<dt>{text(k)}</dt><dd>{text(v)}</dd>' for k, v in facts.items())
    parts.append('</dl>')
    for key in ("blocker", "interruption", "report_error"):
        if status.get(key):
            parts.append(f'<p class="notice"><strong>{text(key)}:</strong> {text(status[key])}</p>')
    if status.get("browser_blockers"):
        parts.append('<p class="notice">Actual browser interactions blocked these modules; screenshots and network records explain each interruption.</p><ul>')
        for blocker in status["browser_blockers"]:
            parts.append('<li>' + text(blocker['name']) + ': ' + text(blocker['reason']) + ' · ' +
                         link('review-' + blocker['id'] + '.html', 'Inspect interaction', download=False) + '</li>')
        parts.append('</ul>')
    if status.get("next_steps"):
        parts.append('<h3>Setup required</h3><pre>' + text('\n'.join(status['next_steps'])) + '</pre><p>'
                     + text(status.get('setup_note', '')) + '</p>')
    parts.append('<div class="cards">' + ''.join(
        f'<div class="card">{badge(outcome)}<span class="number">{counts[outcome]}</span></div>' for outcome in columns) + '</div>')
    parts.append('<p>Counts include every collected attempt. A warning, skip, review, interruption, or unknown result is never counted as passed. '
                 'The runner exit is preserved separately from module counts and harness errors. A nonzero runner result makes the Make target fail.</p><details><summary>How to read outcomes</summary><dl>')
    parts.extend(f'<dt>{badge(k)}</dt><dd>{text(v)}</dd>' for k, v in OUTCOMES.items())
    parts.append('</dl></details><p>' + ' · '.join(link(n) for n in ('execution.json', 'summary.json', 'runner.log', 'unit-tests.log', 'local-e2e.json', 'processes.json')) + '</p></section>')

    if (output / 'consent-policy.json').is_file():
        policy = read('consent-policy.json', {})
        if isinstance(policy, dict) and policy.get('owner') == 'provider':
            explanation = ('The selected go-authcrunch provider supplies the consent page and its security headers; '
                           'Caddy passes them through unchanged. <code>Referrer-Policy: same-origin</code> preserves '
                           'the browser Origin on consent POSTs and withholds cross-origin referrers. The CSP permits '
                           'same-origin styles, images and fonts, a response-specific style nonce, and form submission '
                           'only to self and the registered callback origin. The provider enforces exact registered '
                           'redirect URIs. Origin and CSRF validation remain enabled.')
        else:
            explanation = ('This deployment explicitly sets '
                     '<code>Referrer-Policy: same-origin</code> on successful consent HTML at the issuer’s authorization '
                     'and continuation paths. The v1.2.6 default, <code>no-referrer</code>, makes Chrome submit '
                     '<code>Origin: null</code>, which the provider rejects. Consent form-action allows only self '
                     'and the registered suite callback’s HTTPS origin, so Chrome can follow the code redirect. '
                     'The provider still enforces exact registered redirect URIs. Caddy’s response matcher preserves other '
                     'responses, including form-post callbacks. Origin and CSRF validation remain enabled.')
        parts.append('<section><h2>Caddy consent response policy</h2><p>' + explanation + '</p><p>'
                     + link('consent-policy.json', 'Recorded policy ownership and scope') + ' · '
                     + link('Caddyfile.redacted', 'Deployment configuration') + ' · '
                     + link('local-e2e.json', 'Origin/CSRF rejection preflight') + '</p></section>')

    parts.append('<section id="plans"><h2>Plan results</h2><div class="scroll"><table><thead><tr><th>Plan / recorded definition</th>')
    parts.extend(f'<th>{text(k)}</th>' for k in columns)
    parts.append('<th>Not run</th></tr></thead><tbody>')
    for filename, plan in plans:
        identifiers = {i for m in plan.get("modules", []) for i in m.get("instances", [])}
        plan_counts = Counter(m.get("outcome", m.get("result", "UNKNOWN")) for m in modules if m.get("id") in identifiers)
        not_run = sum(not m.get("instances") for m in plan.get("modules", []))
        parts.append('<tr><td>' + link(filename, plan.get("planName", filename)) + '</td>'
                     + ''.join(f'<td>{plan_counts[k]}</td>' for k in columns) + f'<td>{not_run}</td></tr>')
    parts.append('</tbody></table></div>')
    if not plans:
        parts.append('<p>No plan definitions were collected. See the run state and blocker above.</p>')
    if any(m.get("id") not in membership for m in modules):
        parts.append('<p class="notice">Some instances have no collected plan definition. They remain in the totals and module list.</p>')
    for pending in summary.get("not_run", []):
        parts.append('<p class="notice">NOT_RUN: ' + text(pending.get("module")) + ' · plan ' + text(pending.get("plan")) + '</p>')
    parts.append('</section><section id="modules"><h2>Every module instance</h2><p>Expand each row for the original non-pass condition messages and direct evidence. '
                 'Library capability notes describe the pinned provider; assess them alongside the recorded conditions. Failures need investigation before assigning ownership.</p>')
    for m in sorted(modules, key=lambda m: (membership.get(m.get("id"), ""), m.get("name", ""), m.get("id", ""))):
        identifier, outcome = m.get("id", "unknown"), m.get("outcome", m.get("result", "UNKNOWN"))
        parts.append('<details><summary>' + badge(outcome) + ' ' + text(m.get("name", "Unknown module")) + ' · ' + text(identifier) + '</summary>')
        parts.append('<p>' + text(membership.get(identifier, "Plan definition not collected")) + ' · Status: ' + text(m.get("status", "UNKNOWN")) + '</p>')
        if descriptions.get(identifier):
            parts.append('<p>' + text(descriptions[identifier]) + '</p>')
        parts.append('<p>' + text(OUTCOMES.get(outcome, OUTCOMES["UNKNOWN"])) + '</p>')
        if (m.get("name"), outcome) in CONTEXT:
            parts.append('<p>' + text(CONTEXT[(m["name"], outcome)]) + '</p>')
        parts.append('<pre>' + text(json.dumps(m.get("variant", {}), indent=2, sort_keys=True)) + '</pre>')
        for event in m.get("nonpass_events", []):
            parts.append('<p><strong>' + text(event.get("result", "UNKNOWN")) + ' · ' + text(event.get("src", "suite"))
                         + '</strong><br>' + text(event.get("msg", "See signed export for the full condition.")) + '</p>')
        links = [link('instances/' + identifier + '.json', 'Instance record')]
        links.extend(link(r['file'], 'Screenshots and developer-tools view', download=False)
                     for r in reviews if r['id'] == identifier)
        if m.get("export"):
            links.append(link('exports/' + m["export"], 'Signed export'))
        links.extend(link('visual/' + v['capture'], 'Screenshot' if v['capture'].endswith('.png') else 'Page-source capture') for v in visual if v.get('module_id') == identifier and v.get('capture'))
        parts.append('<p>' + ' · '.join(links) + '</p></details>')
    if not modules:
        parts.append('<p>No module outcomes were collected; this does not mean the plans passed.</p>')
    parts.append('</section><section id="visual"><h2>Visual review and trust limits</h2>')
    if reviews:
        parts.append('<p>Open a review to follow real Chrome screenshots beside navigation, request/response headers, redirects and original suite checks. '
                     'Each review identifies its official image slot and whether signed-export verification completed. REVIEW still requires human assessment.</p><div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">')
        for r in reviews:
            parts.append('<div class="card"><h3>' + text(r['name']) + '</h3><p>' + text(r['mode']) + ' · ' + text(r['id']) + '</p>')
            if r['uploads']:
                capture = r['uploads'][0]['screenshot']
                # render_reviews already validates every local capture path.
                parts.append('<a href="./' + quote(r['file'], safe='/') + '"><img style="width:100%;border:1px solid #d6dfeb" '
                             'alt="Official review screenshot" src="./' + quote(capture, safe='/') + '"></a>')
            parts.append('<p>' + link(r['file'], 'Open screenshots and network timeline', download=False) + '</p></div>')
        parts.append('</div>')
    parts.append('<p>Evidence below preserves its original format: PNG screenshots are real browser captures; HtmlUnit page source is text, '
                 'not a raster screenshot. Neither format is a review approval.</p><ul>')
    for v in visual:
        label = 'Real browser PNG' if v.get('capture', '').endswith('.png') else 'Actual page source'
        parts.append('<li>' + text(v.get('module', v.get('module_id', 'Unknown module'))) + ' · ' + text(v.get('module_id', '')) + ': '
                     + (link('visual/' + v['capture'], label) if v.get('capture') else 'Unfilled placeholder: ' + text(v.get('unfilled_placeholder', 'Unknown'))) + '</li>')
    parts.append('</ul><p>The preflight, Python runner and screenshot browser use trusted HTTPS. The unmodified suite has permissive HTTP and HtmlUnit TLS clients; '
                 'its Config plan and Java truststore alone do not prove complete TLS qualification. See ' + link('tls.json', 'recorded trust controls') +
                 ' and ' + link('browser-tls.json', 'browser trust controls') + '.</p></section>')

    parts.append('<section id="provenance"><h2>Candidate and suite provenance</h2><dl>')
    provenance = {'Caddy-security commit': candidate.get('commit', 'Not recorded'),
                  'Caddy binary SHA-256': candidate.get('binary_sha256', 'Not recorded'),
                  'Go toolchain': candidate.get('go_version', 'Not recorded'),
                  'Suite revision': status.get('suite_revision', candidate.get('suite_revision', 'Not recorded'))}
    for name, dep in candidate.get('dependencies', {}).items():
        provenance[name] = str(dep.get('Version', 'Unknown')) + ' · ' + str(dep.get('Origin', {}).get('Hash', 'origin not recorded'))
    parts.extend(f'<dt>{text(k)}</dt><dd><code>{text(v)}</code></dd>' for k, v in provenance.items())
    parts.append('</dl><p>The commit alone does not identify a dirty candidate; retain the source manifest, patch and actual binary. '
                 'The suite development export key is not Foundation attestation.</p><p>'
                 + ' · '.join(link(n) for n in ('candidate.json', 'source-manifest.json', 'candidate.patch', 'build.txt', 'suite-build.properties', 'tools.json', 'prerequisites.json')) + '</p></section>')

    parts.append('<section id="artifacts"><h2>All artifacts</h2><p>Links are relative so the complete bundle can be moved together. '
                 'Raw files download without embedding executable captured HTML or fetching external resources. Sensitive configuration, tokens, keys and databases are included.</p>')
    groups = defaultdict(list)
    names = {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file() and p.name != 'index.html'}
    names.add('evidence-sha256.json')
    for name in sorted(names):
        groups[name.split('/')[0] if '/' in name else 'Run files'].append(name)
    for group, files in sorted(groups.items(), key=lambda pair: (pair[0] != 'Run files', pair[0])):
        parts.append('<details' + (' open' if group == 'Run files' else '') + '><summary>' + text(group) + f' ({len(files)} files)</summary><ul>')
        parts.extend('<li>' + link(name) + (' — ' + text(DESCRIPTIONS[name]) if name in DESCRIPTIONS else '') + '</li>' for name in files)
        parts.append('</ul></details>')
    if issues:
        parts.append('<p class="notice">Report input issues: ' + text(' '.join(issues)) + '</p>')
    parts.append('</section><footer class="muted">Generated from this run’s local evidence. Outcome labels and runner status are never rewritten.</footer></main></body></html>')
    return '\n'.join(parts)
