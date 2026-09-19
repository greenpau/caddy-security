#!/usr/bin/env python3
"""Private, local Foundation OP rehearsal against a freshly built Caddy binary.

See .codex/skills/configuration-oauth-applications/references/oidc-conformance.md.
The official runner and validators are never patched. Nonzero runner exits are
returned unchanged; evidence collection has its own independent failure state.
"""

import argparse
import base64
import collections
import hashlib
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from oidc_conformance_report import render_report
from oidc_conformance_browser_tools import chrome_binary
from oidc_conformance_artifacts import ArtifactError, mark_output, workspace_lock


ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "tmp" / "oidc-conformance"
REVISION = "e3b5558d6d5e0c17ab578a47b955fd3b405f902b"
PLANS = (
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
    "oidcc-config-certification-test-plan",
    "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
)
CLIENTS = {"client": "client_secret_basic", "client2": "client_secret_basic",
           "client_secret_post": "client_secret_post"}


class Blocker(RuntimeError):
    """An explicit prerequisite or harness failure, never a passing result."""


class PreparationRequired(Blocker):
    """A missing downloaded prerequisite with an actionable preparation step."""


def private_write(path, value):
    data = value if isinstance(value, bytes) else value.encode()
    with open(path, "wb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def write_json(path, value):
    private_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inside_tmp(path, new=False):
    """Reject symlink escapes and existing result paths before any writes."""
    path = Path(os.path.abspath(path))
    tmp = (ROOT / "tmp").resolve(strict=True)
    parent = path.parent.resolve(strict=False) if new else path.resolve(strict=True)
    if not parent.is_relative_to(tmp) or parent == tmp and not new:
        raise Blocker("suite, tools, and evidence must be below this repository's tmp directory")
    if new and (path.exists() or path.is_symlink()):
        raise Blocker("result directory must be new; prior evidence cannot be overwritten")
    return parent / path.name if new else parent


def command(args, *, cwd=ROOT, env=None, timeout=120):
    child = subprocess.Popen([str(a) for a in args], cwd=cwd, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
        result = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
        result.check_returncode()
        return result
    finally:
        Processes.stop(child)


def suite_check(suite):
    suite = inside_tmp(suite)
    if command(["git", "rev-parse", "HEAD"], cwd=suite).stdout.decode().strip() != REVISION:
        raise Blocker("Foundation suite revision must be " + REVISION)
    if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=suite).stdout:
        raise Blocker("Foundation suite source must be unmodified, including untracked files")
    return suite


def jar_check(suite):
    jar = suite / "target/fapi-test-suite.jar"
    if not jar.is_file():
        raise PreparationRequired("missing suite target/fapi-test-suite.jar")
    with zipfile.ZipFile(jar) as archive:
        metadata = archive.read("BOOT-INF/classes/git.properties").decode()
    properties = dict(line.split("=", 1) for line in metadata.splitlines() if "=" in line and not line.startswith("#"))
    if properties.get("git.commit.id") != REVISION or properties.get("git.dirty") != "false":
        raise Blocker("suite jar was not built from the pinned clean revision")
    return metadata


def runner_environment(base, ca, temp, token):
    env = os.environ.copy()
    # Do not inherit a developer's settings that suppress tests, retry failures,
    # disable TLS, or route credentials through an unrelated proxy.
    for key in list(env):
        if key.startswith("CONFORMANCE_") or key in (
                "DISABLE_SSL_VERIFY", "EXTERNAL_URL", "HTTP_PROXY", "HTTPS_PROXY",
                "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
                "SSL_CERT_DIR", "PYTHONPATH", "PYTHONHOME", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"):
            env.pop(key)
    env.update(CONFORMANCE_SERVER=base + "/", CONFORMANCE_SERVER_MTLS=base + "/",
               CONFORMANCE_TOKEN=token, SSL_CERT_FILE=str(ca),
               CONFORMANCE_MAX_CONSECUTIVE_FAILURES="1000", CONFORMANCE_RESTART_RETRIES="0",
               PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(temp), NO_PROXY="127.0.0.1,localhost")
    return env


class Processes:
    def __init__(self, output):
        self.output, self.children = output, []

    def start(self, name, args, *, env=None, cwd=ROOT):
        log = open(self.output / (name + ".log"), "xb")
        os.chmod(log.name, 0o600)
        try:
            child = subprocess.Popen([str(a) for a in args], cwd=cwd, env=env,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()
        self.children.append((name, child))
        return child

    @staticmethod
    def stop(child):
        # The leader can exit while a compiler/helper in its owned group lives.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if child.poll() is None:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)

    def close(self):
        for _, child in reversed(self.children):
            self.stop(child)
        write_json(self.output / "processes.json", [
            {"name": name, "pid": child.pid, "exit_code": child.returncode, "reaped": child.poll() is not None}
            for name, child in self.children])


def ports(count):
    # Reserve together so independently chosen ephemeral ports cannot repeat.
    listeners = [socket.socket() for _ in range(count)]
    try:
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def make_pki(output):
    ca, cert, key = [output / n for n in ("ca.pem", "tls.pem", "tls.key")]
    private_write(output / "ca.cnf", "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
                  "[dn]\nCN=Caddy conformance disposable CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
                  "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    private_write(output / "leaf.cnf", "[leaf]\nbasicConstraints=critical,CA:FALSE\n"
                  "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                  "subjectAltName=DNS:localhost,IP:127.0.0.1\n")
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-config", output / "ca.cnf", "-keyout", output / "ca.key", "-out", ca])
    command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", key, "-out", output / "tls.csr"])
    command(["openssl", "x509", "-req", "-in", output / "tls.csr", "-CA", ca,
             "-CAkey", output / "ca.key", "-CAcreateserial", "-days", "2", "-sha256",
             "-extfile", output / "leaf.cnf", "-extensions", "leaf", "-out", cert])
    return ca, cert, key


def registration_body(method, callback):
    return (f"token_endpoint_auth_method {method}\nredirect_uri {callback}\n"
            "scopes openid profile email address phone offline_access\nrequire_pkce false\n")


def verify_registrations(clients, callback):
    """Check the persisted CLI output before using it in any official plan."""
    if set(clients) != set(CLIENTS):
        raise Blocker("conformance requires exactly the three static client registrations")
    for name, method in CLIENTS.items():
        client = clients[name]
        if any(not isinstance(client.get(key), str) or not client[key]
               for key in ("client_id", "client_secret")):
            raise Blocker("conformance registration lacks confidential client credentials")
        if client.get("token_endpoint_auth_method") != method:
            raise Blocker("conformance registration has the wrong client authentication method")
        if client.get("redirect_uris") != [callback]:
            raise Blocker("conformance registration must contain only the exact suite callback")
        # The persisted Go representation omits false booleans. The source
        # registration_body explicitly disables PKCE for these fixtures only.
        if (client.get("require_pkce", False) is not False or
                client.get("skip_consent", False) is not False):
            raise Blocker("conformance client must allow Basic profile requests and require consent")
    for field in ("client_id", "client_secret"):
        if len({client[field] for client in clients.values()}) != len(CLIENTS):
            raise Blocker("conformance registrations must have distinct client IDs and secrets")
    # Record the verified contract without duplicating credential material.
    return {"callback": callback, "distinct_client_ids": len(clients),
            "distinct_client_secrets": len(clients), "clients": [
                {"name": name, "revision": "v1", "token_endpoint_auth_method": method,
                 "redirect_uris": [callback], "require_pkce": False, "skip_consent": False}
                for name, method in CLIENTS.items()]}


def provision(binary, output, callback, env):
    store = f'oauth registration store {{\npath "{output / "registrations"}"\n}}\n'
    store_file = output / "oauth_store.Caddyfile"
    private_write(store_file, store)
    command([binary, "security", "oauth", "init", "provisioning", "store", "--config", store_file], env=env)
    applications, config, registrations = "", {}, {}
    for name, method in CLIENTS.items():
        body = registration_body(method, callback)
        source = output / (name + ".Caddyfile")
        private_write(source, store + f"oauth application {name} {{\n{body}}}\n")
        record = command([binary, "security", "oauth", "create", "application", "--config", source,
                          "--name", name, "--revision", "v1"], env=env).stdout.decode().strip()
        client = json.loads(Path(record).read_text())["client"]
        registrations[name] = client
        applications += f"oauth application {name} {{\nregistration v1\n{body}}}\n"
    write_json(output / "registration-evidence.json", verify_registrations(registrations, callback))
    for name, client in registrations.items():
        config[name] = {"client_id": client["client_id"], "client_secret": client["client_secret"],
                        "scope": "openid profile email"}
    key = command([binary, "security", "oidc", "create", "signing", "key", "--config", store_file,
                   "--name", "conformance", "--revision", "k1"], env=env).stdout.decode().strip()
    return store + applications, key, config


def deployment(output, op_port, suite_port, java_port, declarations, signing_key, password, portal_secret):
    return f'''{{
admin off
persist_config off
auto_https off
security {{
{declarations}
local identity store localdb {{
realm local
path "{output / 'users.json'}"
user conformance {{
name "Conformance User"
email conformance@example.test
password {password}
roles authp/user
}}
}}
authentication portal conformance {{
enable identity store localdb
crypto key sign-verify {portal_secret}
cookie path /auth
oidc provider {{
issuer https://127.0.0.1:{op_port}/auth
realms local
signing key files "{signing_key}"
applications client client2 client_secret_post
acr urn:authcrunch:password pwd
}}
}}
}}
}}
https://127.0.0.1:{op_port} {{
bind 127.0.0.1
tls "{output / 'tls.pem'}" "{output / 'tls.key'}"
@portal path /auth /auth/*
route @portal {{
authenticate with conformance
}}
respond 404
}}
https://127.0.0.1:{suite_port} {{
bind 127.0.0.1
tls "{output / 'tls.pem'}" "{output / 'tls.key'}"
log {{
output file "{output / 'suite-access.private.jsonl'}" {{
roll_disabled
}}
format json
}}
reverse_proxy 127.0.0.1:{java_port} {{
header_up X-Forwarded-Proto https
header_up X-Forwarded-Host {{http.request.hostport}}
header_up X-Forwarded-Port {suite_port}
header_up X-Forwarded-Uri {{http.request.uri}}
header_up X-Ssl-Protocol {{http.request.tls.version}}
header_up X-Ssl-Cipher {{http.request.tls.cipher_suite}}
}}
}}
'''


def redact(value):
    if isinstance(value, dict):
        return {key: "REDACTED" if key in ("client_secret", "password", "secret", "token") else redact(child)
                for key, child in value.items()}
    if isinstance(value, list):
        return [redact(child) for child in value]
    return value


def plan_config(config, issuer, base, password):
    config.update(alias="caddy-local", description="Caddy candidate; local unmodified OIDF " + REVISION,
                  server={"discoveryUrl": issuer + "/.well-known/openid-configuration"})
    config["browser"] = [{"match": issuer + "*", "tasks": [
        {"task": "Real password login / reauthentication", "optional": True, "match": issuer + "/login*",
         "commands": [["text", "name", "username", "conformance"], ["click", "class", "app-btn-pri"]]},
        {"task": "Password challenge", "optional": True, "match": issuer + "/sandbox/*",
         "commands": [["text", "name", "secret", password], ["click", "name", "submit"]]},
        {"task": "Explicit consent", "optional": True, "match": issuer + "/oidc/*",
         "commands": [["click", "name", "decision"]]},
        {"task": "Suite callback", "optional": True, "match": base + "/test/*/callback*",
         "commands": [["wait", "id", "submission_complete", 10]]},
    ]}]
    # These are browser actions for real rejection pages, not outcome overrides.
    config["override"] = {name: {"browser": [{"match": issuer + "*", "tasks": [
        {"task": "Capture actual redirect rejection", "match": issuer + "/oidc/authorize*",
         "commands": [["wait", "xpath", "//*", 10, "invalid_request", "update-image-placeholder"]]}
    ]}]} for name in ("oidcc-ensure-registered-redirect-uri", "oidcc-ensure-redirect-uri-in-authorization-request",
                      "oidcc-redirect-uri-query-added", "oidcc-redirect-uri-query-mismatch")}
    # Use the suite's supported manual-browser path for visual review. A
    # separate real Chrome session drives the actual URLs and uploads PNGs.
    for name in ("oidcc-prompt-login", "oidcc-max-age-1", "oidcc-ensure-registered-redirect-uri"):
        config["override"][name] = {"browser": []}
    return config


def seed_profile(output):
    """Add explicit synthetic attributes to the disposable Caddy-created user."""
    path = output / "users.json"
    database = json.loads(path.read_text())
    users = [u for u in database["users"] if u["username"] == "conformance"]
    if len(users) != 1:
        raise Blocker("Caddy did not provision the unique conformance identity")
    users[0]["profile"] = {
        "given_name": "Conformance", "family_name": "User", "middle_name": "Local", "nickname": "Test",
        "profile": "https://example.test/conformance", "picture": "https://example.test/avatar.png",
        "website": "https://example.test", "gender": "unspecified", "birthdate": "2000-01-01",
        "zoneinfo": "America/New_York", "locale": "en-US", "updated_at": 1700000000,
        "phone_number": "+1 202-555-0100", "phone_number_verified": False,
        "address": {"formatted": "1 Example Street, Testville", "street_address": "1 Example Street",
                    "locality": "Testville", "region": "Test", "postal_code": "00000", "country": "US"},
    }
    write_json(path, database)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Browser:
    def __init__(self, ca):
        self.context = ssl.create_default_context(cafile=str(ca))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

    def request(self, url, data=None, headers=None, method=None):
        body = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read(32 << 20)

    def json(self, url):
        status, _, data = self.request(url)
        if status != 200:
            raise Blocker(f"evidence API returned HTTP {status}")
        return json.loads(data)


class Form(html.parser.HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.action, self.values, self.decisions = "", {}, []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action", "")
        if tag == "input" and attrs.get("type") == "hidden":
            self.values[attrs["name"]] = attrs.get("value", "")
        if tag in ("button", "input") and attrs.get("name") == "decision":
            self.decisions.append(attrs.get("value"))


def validate_consent_policy(headers, callback):
    """Check protocol restrictions while allowing the provider's themed styles."""
    if headers.get("Referrer-Policy") != "same-origin":
        raise Blocker("local consent page must preserve browser Origin with Referrer-Policy: same-origin")
    directives = {}
    for entry in headers.get("Content-Security-Policy", "").split(";"):
        fields = entry.split()
        if not fields:
            continue
        if fields[0] in directives:
            raise Blocker("duplicate local consent CSP directive")
        directives[fields[0]] = fields[1:]
    target = urllib.parse.urlsplit(callback)
    expected = {"default-src": ["'none'"], "frame-ancestors": ["'none'"], "base-uri": ["'none'"],
                "form-action": ["'self'", target.scheme + "://" + target.netloc]}
    # The current provider uses a per-response style nonce and same-origin
    # assets. Legacy unstyled consent remains acceptable; scripts never are.
    if "style-src" in directives:
        styles = directives["style-src"]
        if len(styles) != 2 or styles[0] != "'self'" or not re.fullmatch(r"'nonce-[A-Za-z0-9_-]{22,}'", styles[1]):
            raise Blocker("local consent CSP has unsafe stylesheet sources")
        expected.update({"style-src": styles, "img-src": ["'self'"], "font-src": ["'self'"]})
    if directives != expected:
        raise Blocker("local consent CSP must restrict assets and allow form submission only to self and the registered callback origin")


def smoke(output, ca, issuer, callback, clients, password):
    """Preflight actual Caddy password/consent before the opt-in official plans."""
    browser = Browser(ca)
    evidence = []
    for name in CLIENTS:
        params = dict(client_id=clients[name]["client_id"], redirect_uri=callback, response_type="code",
                      scope="openid profile email", state=secrets.token_urlsafe(24), nonce=secrets.token_urlsafe(24),
                      prompt="login")
        url = issuer + "/oidc/authorize?" + urllib.parse.urlencode(params)
        response = browser.request(url)
        seen = {"password": False, "consent": False}
        code = None
        for _ in range(25):
            status, headers, body = response
            if status in (302, 303):
                url = urllib.parse.urljoin(url, headers["Location"])
                if url.startswith(callback + "?"):
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                    if query.get("state") != [params["state"]] or query.get("iss") != [issuer]:
                        raise Blocker("local callback binding failed")
                    code = query["code"][0]
                    break
                if not url.startswith(issuer + "/"):
                    raise Blocker("local browser left the configured issuer")
                response = browser.request(url)
            elif status == 200 and "/login" in url:
                response = browser.request(url, {"username": "conformance", "realm": "local"})
            elif status == 200 and "/sandbox/" in url:
                seen["password"] = True
                response = browser.request(url, {"secret": password})
            elif status == 200 and urllib.parse.urlsplit(url).path in (
                    urllib.parse.urlsplit(issuer).path + "/oidc/authorize",
                    urllib.parse.urlsplit(issuer).path + "/oidc/continue"):
                form = Form(body.decode())
                if form.action != issuer + "/oidc/continue" or not form.values.get("csrf") or "allow" not in form.decisions:
                    raise Blocker("local consent form missing its action, CSRF or approval control")
                validate_consent_policy(headers, callback)
                target = urllib.parse.urlsplit(callback)
                origin = urllib.parse.urlsplit(issuer)
                origin = origin.scheme + "://" + origin.netloc
                for supplied_origin, csrf in (("null", form.values["csrf"]),
                                               ("https://attacker.example", form.values["csrf"]),
                                               (origin, "forged")):
                    rejected, _, _ = browser.request(form.action, dict(form.values, decision="allow", csrf=csrf),
                                                     {"Origin": supplied_origin})
                    if rejected != 403:
                        raise Blocker("local consent Origin/CSRF rejection failed")
                seen["consent"] = True
                response = browser.request(form.action, dict(form.values, decision="allow"), {"Origin": origin})
            else:
                raise Blocker(f"local browser stalled with HTTP {status}")
        if not code or not all(seen.values()):
            raise Blocker("local flow omitted password, consent or authorization code")
        data = dict(grant_type="authorization_code", code=code, redirect_uri=callback)
        headers = {}
        client = clients[name]
        if name == "client_secret_post":
            data.update(client_id=client["client_id"], client_secret=client["client_secret"])
        else:
            headers["Authorization"] = "Basic " + base64.b64encode(
                (client["client_id"] + ":" + client["client_secret"]).encode()).decode()
        status, _, body = browser.request(issuer + "/oidc/token", data, headers)
        if status != 200 or not json.loads(body).get("id_token"):
            raise Blocker("local code exchange failed")
        status, _, _ = browser.request(issuer + "/oidc/token", data, headers)
        if status != 400:
            raise Blocker("local code replay was accepted")
        evidence.append({"client": name, **seen, "code_exchange": True, "replay_rejected": True,
                         "consent_referrer_policy": "same-origin", "null_origin_rejected": True,
                         "consent_form_action": ["'self'", target.scheme + "://" + target.netloc],
                         "cross_origin_rejected": True, "forged_csrf_rejected": True})
    write_json(output / "local-e2e.json", evidence)


def wait_ready(browser, url, child, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise Blocker("owned process exited before readiness; inspect its private log")
        try:
            if browser.request(url)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise Blocker("HTTPS readiness deadline expired; inspect private process logs")


def source_evidence(output, binary):
    paths = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).stdout
    manifest = {name: digest(ROOT / name) if (ROOT / name).is_file() else "deleted"
                for name in paths.decode().split("\0") if name}
    write_json(output / "source-manifest.json", manifest)
    with tarfile.open(output / "source.tar.gz", "w:gz") as archive:
        for name, checksum in manifest.items():
            if checksum != "deleted":
                archive.add(ROOT / name, arcname=name, recursive=False)
    private_write(output / "candidate.patch", command(["git", "diff", "HEAD", "--binary"]).stdout)
    private_write(output / "build.txt", command(["go", "version", "-m", binary]).stdout)
    dependencies = {}
    for name in ("github.com/caddyserver/caddy/v2", "github.com/greenpau/go-authcrunch"):
        dep = json.loads(command(["go", "list", "-m", "-json", name]).stdout)
        if "Replace" in dep:
            raise Blocker("official rehearsal requires pinned module dependencies, without local replacements")
        info = json.loads(command(["go", "mod", "download", "-json", name + "@" + dep["Version"]]).stdout)
        dependencies[name] = {k: v for k, v in info.items() if k in ("Path", "Version", "Sum", "GoModSum", "Origin")}
    write_json(output / "candidate.json", {
        "commit": command(["git", "rev-parse", "HEAD"]).stdout.decode().strip(),
        "binary_sha256": digest(binary), "suite_revision": REVISION,
        "source_manifest_sha256": digest(output / "source-manifest.json"), "dependencies": dependencies,
        "go_version": command(["go", "version"]).stdout.decode().strip(),
        "host": "cmd/authcrunch: actual Caddy security app and authenticate route",
    })


def summarize_exports(exports):
    """Never classify warning/review/skip/interruption as passed or drop attempts."""
    modules = []
    for path in sorted(exports.glob("*.zip")):
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise Blocker("corrupt official export: " + path.name)
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                data = json.loads(archive.read(name))
                info = data["testInfo"]
                sig = name.removesuffix(".json") + ".sig"
                if sig not in archive.namelist() or not archive.read(sig):
                    raise Blocker("official export is missing its signature")
                modules.append({"id": info["testId"], "name": info["testName"],
                    "result": info.get("result") or "UNKNOWN", "status": info.get("status") or "UNKNOWN",
                    "outcome": "INTERRUPTED" if info.get("status") == "INTERRUPTED" else info.get("result") or "UNKNOWN",
                    "variant": info.get("variant"), "export": path.name, "member": name,
                    "nonpass_events": [r for r in data["results"] if r.get("result") in
                                       ("WARNING", "SKIPPED", "REVIEW", "FAILURE", "FAILED", "INTERRUPTED")]})
    # Plan and per-instance exports overlap. Keep every instance, never choose a
    # successful retry in preference to an earlier failure of the same module.
    unique = {}
    for module in modules:
        if module["id"] in unique and unique[module["id"]]["result"] != module["result"]:
            raise Blocker("conflicting export outcomes for the same instance")
        unique[module["id"]] = module
    return {"counts": dict(collections.Counter(m["outcome"] for m in unique.values())),
            "modules": list(unique.values()), "module_instances": len(unique)}


def verify_exports(exports, jwks):
    """Independently verify the suite's detached RS256 export signatures."""
    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    verified = 0
    for path in sorted(exports.glob("*.zip")):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                signature = decode(archive.read(name.removesuffix(".json") + ".sig").decode())
                message = archive.read(name)
                valid = False
                for key in jwks["keys"]:
                    if key["kty"] != "RSA":
                        continue
                    modulus = int.from_bytes(decode(key["n"]), "big")
                    exponent = int.from_bytes(decode(key["e"]), "big")
                    size = (modulus.bit_length() + 7) // 8
                    sig = int.from_bytes(signature, "big")
                    if len(signature) != size or sig >= modulus:
                        continue
                    # RFC 8017 EMSA-PKCS1-v1_5 with SHA-256 DigestInfo.
                    suffix = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
                    padding = size - len(suffix) - 3
                    if padding >= 8 and pow(sig, exponent, modulus).to_bytes(size, "big") == b"\x00\x01" + b"\xff" * padding + b"\x00" + suffix:
                        valid = True
                        break
                if not valid:
                    raise Blocker("invalid official export signature: " + path.name + "/" + name)
                verified += 1
    if not verified:
        raise Blocker("no signed module exports collected")
    return verified


def run_runner(processes, args, workdir, env, timeout, status, reviewer=None):
    runner = processes.start("runner", args, cwd=workdir, env=env)
    try:
        deadline = time.monotonic() + timeout
        while runner.poll() is None:
            if reviewer is not None and reviewer.poll() is not None:
                status["interruption"] = "review browser exited before runner; inspect review-browser-error.log"
                processes.stop(runner)
                break
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(args, timeout)
            time.sleep(.2)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        status["interruption"] = type(error).__name__
        processes.stop(runner)
    finally:
        status["runner_exit_code"] = runner.poll()
    return runner.returncode if runner.returncode >= 0 else 128 - runner.returncode


def fully_passed(summary, status):
    return (status.get("runner_exit_code") == 0 and not status.get("interruption")
            and summary["plans"] == len(PLANS) and not summary["not_run"]
            and summary["module_instances"] == 71
            and all(module["result"] == "PASSED" and module["status"] == "FINISHED"
                    for module in summary["modules"]))


def collect(browser, base, output):
    listing = browser.json(base + "/api/plan?length=1000")
    write_json(output / "plans.json", listing)
    plans = listing["data"]
    pending = []
    for item in plans:
        plan_id = item["_id"]
        plan = browser.json(base + "/api/plan/" + plan_id)
        write_json(output / ("plan-" + plan_id + ".json"), plan)
        for module in plan["modules"]:
            instances = module.get("instances") or []
            if not instances:
                pending.append({"plan": plan_id, "module": module["testModule"], "result": "NOT_RUN"})
            for test_id in instances:
                info = browser.json(base + "/api/info/" + test_id)
                write_json(output / "instances" / (test_id + ".json"), info)
                status, _, body = browser.request(base + "/api/log/export/" + test_id)
                if status != 200:
                    raise Blocker("could not preserve signed module export " + test_id)
                private_write(output / "exports" / (test_id + ".zip"), body)
    summary = summarize_exports(output / "exports")
    summary["verified_signatures"] = verify_exports(output / "exports", browser.json(base + "/jwks"))
    visual = []
    for module in summary["modules"]:
        with zipfile.ZipFile(output / "exports" / module["export"]) as archive:
            exported = json.loads(archive.read(module["member"]))
        for i, event in enumerate(exported["results"]):
            if "page_source" in event:
                capture = f"{module['id']}-{i}.html.txt"
                private_write(output / "visual" / capture, event["page_source"])
                visual.append({"module_id": module["id"], "module": module["name"], "result": module["result"],
                               "source": event.get("src"), "capture": capture,
                               "kind": "official HtmlUnit page source; not a raster screenshot",
                               "export": module["export"], "member": module["member"]})
            elif event.get("img", "").startswith("data:image/png;base64,"):
                capture = f"{module['id']}-{i}.png"
                private_write(output / "visual" / capture, base64.b64decode(event["img"].split(",", 1)[1], validate=True))
                visual.append({"module_id": module["id"], "module": module["name"], "result": module["result"],
                               "source": event.get("src"), "capture": capture, "event_id": event.get("_id"),
                               "kind": "real Chrome screenshot in signed official export",
                               "export": module["export"], "member": module["member"]})
            elif event.get("upload"):
                visual.append({"module_id": module["id"], "module": module["name"],
                               "unfilled_placeholder": event["upload"]})
    write_json(output / "visual-evidence.json", visual)
    summary.update(plans=len(plans), not_run=pending)
    write_json(output / "summary.json", summary)
    return summary


def verify_browser_evidence(output, summary):
    """Every reviewed instance needs the actual requested PNG in its signed log."""
    records = json.loads((output / "browser-evidence.json").read_text())
    visual = json.loads((output / "visual-evidence.json").read_text())
    required = {m["id"] for m in summary["modules"] if m["name"] in
                ("oidcc-prompt-login", "oidcc-max-age-1", "oidcc-ensure-registered-redirect-uri")}
    if len(required) != 6 or {r["id"] for r in records} != required:
        raise Blocker("real browser review evidence is incomplete")
    verified = []
    for record in records:
        if record.get("blocker") and not record["uploads"]:
            continue
        if len(record["uploads"]) != 1:
            raise Blocker("review module lacks exactly one matching screenshot upload")
        upload = record["uploads"][0]
        matches = [v for v in visual if v.get("module_id") == record["id"]
                   and v.get("event_id") == upload["event_id"] and v.get("capture", "").endswith(".png")]
        if len(matches) != 1 or digest(output / "visual" / matches[0]["capture"]) != upload["sha256"]:
            raise Blocker("signed official screenshot differs from original browser capture")
        verified.append({"module_id": record["id"], "event_id": upload["event_id"], "sha256": upload["sha256"]})
    write_json(output / "browser-export-verification.json", verified)


def run(args):
    with workspace_lock(ROOT, "run"):
        return run_locked(args)


def run_locked(args):
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = inside_tmp(args.results, new=True)
    mark_output(ROOT, output, args)
    print("Private evidence: " + str(output), flush=True)
    processes = Processes(output)
    status = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "suite_revision": REVISION, "local_only": args.local_only, "runner_exit_code": None,
              "state": "STARTING", "certification": False}
    browser, base = None, None
    exit_code = 2
    try:
        for executable in ("go", "git", "openssl"):
            if not shutil.which(executable):
                raise Blocker("missing executable: " + executable)
        try:
            units = command([sys.executable, "-m", "unittest", "discover", "-s",
                             "assets/scripts/oidc_certification_conformance_tests", "-p", "test_oidc_conformance_*.py", "-v"], timeout=60)
            private_write(output / "unit-tests.log", units.stdout + units.stderr)
        except subprocess.CalledProcessError as error:
            private_write(output / "unit-tests.log", error.stdout + error.stderr)
            raise Blocker("conformance harness unit tests failed; inspect private unit-tests.log") from error
        suite = None
        if not args.local_only:
            if not args.suite.is_dir():
                raise PreparationRequired("missing pinned suite checkout: " + str(args.suite))
            suite = suite_check(args.suite)
            for label in ("java", "mongod", "runner_python", "chrome", "chromedriver"):
                path = Path(getattr(args, label))
                if not path.is_file() or not os.access(path, os.X_OK):
                    raise PreparationRequired("missing prerequisite --" + label.replace("_", "-") + ": " + str(path))
                inside_tmp(path.parent)
                setattr(args, label, path.absolute())
            private_write(output / "suite-build.properties", jar_check(suite))
            try:
                command([args.runner_python, "-c", "import httpx, pyparsing, websocket"])
            except subprocess.CalledProcessError as error:
                raise PreparationRequired("isolated runner Python lacks required HTTP/browser packages") from error
            if (WORK / "prerequisites.json").is_file():
                private_write(output / "prerequisites.json", (WORK / "prerequisites.json").read_bytes())
        for directory in ("runtime", "exports", "instances", "mongodb", "visual"):
            (output / directory).mkdir(mode=0o700)
        env = os.environ.copy()
        env.update(XDG_DATA_HOME=str(output / "runtime/data"), XDG_CONFIG_HOME=str(output / "runtime/config"),
                   TMPDIR=str(output / "runtime"))
        binary = output / "caddy"
        build = command(["go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch"],
                        env=env, timeout=300)
        private_write(output / "build.log", build.stdout + build.stderr)
        source_evidence(output, binary)
        ca, _, _ = make_pki(output)
        op_port, suite_port, java_port, mongo_port = ports(4)
        issuer, base = f"https://127.0.0.1:{op_port}/auth", f"https://127.0.0.1:{suite_port}"
        callback = base + "/test/a/caddy-local/callback"
        declarations, signing_key, clients = provision(binary, output, callback, env)
        password, portal_secret = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        source = deployment(output, op_port, suite_port, java_port, declarations, signing_key, password, portal_secret)
        config_file = output / "Caddyfile"
        private_write(config_file, source)
        private_write(output / "Caddyfile.redacted", source.replace(password, "REDACTED").replace(portal_secret, "REDACTED"))
        write_json(output / "consent-policy.json", {
            "source": "github.com/greenpau/go-authcrunch/pkg/oidc/pages.go",
            "owner": "provider", "provenance": "candidate.json",
            "method": "GET", "paths": ["/auth/oidc/authorize", "/auth/oidc/continue"],
            "policy": "same-origin",
            "form_action": ["'self'", base],
            "scope": "Provider consent HTML; Caddy preserves the provider's security headers",
        })
        adapted = command([binary, "adapt", "--config", config_file, "--adapter", "caddyfile"], env=env)
        private_write(output / "deployment.private.json", adapted.stdout)
        redacted = redact(json.loads(adapted.stdout))
        private_write(output / "deployment.redacted.json", json.dumps(redacted, indent=2).replace(portal_secret, "REDACTED"))
        private_write(output / "adapt.log", adapted.stderr)
        # Caddy provisions and closes its local store during validation. Add
        # fixture attributes offline before the serving process opens that store.
        validated = command([binary, "validate", "--config", output / "deployment.private.json"], env=env)
        private_write(output / "validate.log", validated.stdout + validated.stderr)
        seed_profile(output)
        caddy = processes.start("caddy", [binary, "run", "--config", output / "deployment.private.json"], env=env)
        browser = Browser(ca)
        wait_ready(browser, issuer + "/.well-known/openid-configuration", caddy, timeout=30)
        discovery = browser.json(issuer + "/.well-known/openid-configuration")
        if discovery["issuer"] != issuer:
            raise Blocker("Caddy discovery issuer differs from configured mount")
        write_json(output / "discovery.json", discovery)
        write_json(output / "op-jwks.json", browser.json(discovery["jwks_uri"]))
        # Proof that our transport does not accept this private CA implicitly.
        try:
            with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", timeout=5):
                raise Blocker("negative TLS trust control unexpectedly succeeded")
        except urllib.error.URLError as error:
            if not isinstance(error.reason, ssl.SSLCertVerificationError):
                raise
        write_json(output / "tls.json", {"ca_sha256": digest(ca), "trusted_https": True,
                                        "untrusted_ca_rejected": True, "issuer": issuer, "suite": base})
        smoke(output, ca, issuer, callback, clients, password)
        if args.local_only:
            status["state"], exit_code = "LOCAL_E2E_COMPLETE", 0
        else:
            plan = plan_config(clients, issuer, base, password)
            write_json(output / "plan.private.json", plan)
            keytool = Path(args.java).parent / "keytool"
            command([keytool, "-importcert", "-noprompt", "-alias", "caddy-conformance", "-file", ca,
                     "-keystore", output / "trust.p12", "-storepass", "conformance", "-storetype", "PKCS12"])
            processes.start("mongodb", [args.mongod, "--dbpath", output / "mongodb", "--bind_ip", "127.0.0.1",
                                         "--port", str(mongo_port), "--quiet"], env=env)
            java = processes.start("suite", [args.java, "-Xmx2g", "-Djava.io.tmpdir=" + str(output / "runtime"),
                "-Djavax.net.ssl.trustStore=" + str(output / "trust.p12"), "-Djavax.net.ssl.trustStorePassword=conformance",
                "-jar", suite / "target/fapi-test-suite.jar", "--spring.profiles.active=dev",
                "--fintechlabs.makeDummyUserAdminInDevMode=false",
                "--server.address=127.0.0.1", "--server.port=" + str(java_port),
                f"--spring.mongodb.uri=mongodb://127.0.0.1:{mongo_port}/caddy_conformance",
                "--openid.mongodb.targetFeatureCompatibilityVersion=7.0", "--fintechlabs.base_url=" + base,
                "--fintechlabs.base_mtls_url=" + base, "--logging.level.net.openid.conformance=INFO"], env=env, cwd=suite)
            wait_ready(browser, base + "/api/plan?length=1", java)
            write_json(output / "suite-server.json", browser.json(base + "/api/server"))
            write_json(output / "suite-jwks.json", browser.json(base + "/jwks"))
            token_status, _, token_body = browser.request(base + "/api/token", b"{}", {"Content-Type": "application/json"})
            if token_status != 201:
                raise Blocker("local suite API token creation failed")
            private_write(output / "suite-token.private.json", token_body)
            suite_token = json.loads(token_body)["token"]
            write_json(output / "tools.json", {"java": command([args.java, "-version"]).stderr.decode(),
                "mongod": command([args.mongod, "--version"]).stdout.decode(),
                "python": command([args.runner_python, "--version"]).stdout.decode(),
                "packages": command([args.runner_python, "-m", "pip", "freeze"]).stdout.decode(),
                "jar_sha256": digest(suite / "target/fapi-test-suite.jar")})
            browser_config = dict(output=str(output), ca=str(ca), issuer=issuer, base=base, password=password,
                                  chrome=str(args.chrome), chromedriver=str(args.chromedriver))
            write_json(output / "review-browser.private.json", browser_config)
            reviewer = processes.start("review-browser", [args.runner_python,
                ROOT / "assets/scripts/oidc_conformance_browser.py", output / "review-browser.private.json"], env=env)
            deadline = time.monotonic() + 120
            while not (output / "review-browser.ready").exists():
                if reviewer.poll() is not None or time.monotonic() > deadline:
                    raise Blocker("review browser prerequisite failed; inspect private review-browser-error.log and chromedriver.log")
                time.sleep(.2)
            # The pinned runner reparses plan arguments with a whitespace
            # grammar. Use simple relative names from the private run directory
            # so artifact destinations with spaces work without patching it.
            runner_args = [str(args.runner_python), str(suite / "scripts/run-test-plan.py"), "--no-parallel",
                           "--export-dir", "exports"]
            for plan_name in PLANS:
                runner_args += [plan_name, "plan.private.json"]
            write_json(output / "runner-command.json", runner_args)
            write_json(output / "runner-working-directory.json", str(output))
            status["state"] = "RUNNING"
            write_json(output / "execution.json", status)
            exit_code = run_runner(processes, runner_args, output,
                                  runner_environment(base, ca, output / "runtime", suite_token), args.timeout, status, reviewer)
            private_write(output / "review-browser.stop", "stop\n")
            reviewer.wait(timeout=60)
            status["state"] = "RUNNER_FINISHED"
            summary = collect(browser, base, output)
            status["counts"] = summary["counts"]
            if reviewer.returncode != 0:
                raise Blocker("review browser failed; inspect private review-browser-error.log")
            browser_records = json.loads((output / "browser-evidence.json").read_text())
            status["browser_blockers"] = [{"id": r["id"], "name": r["name"], "reason": r["blocker"]}
                                          for r in browser_records if r.get("blocker")]
            print("Official module outcomes: " + json.dumps(summary["counts"], sort_keys=True), flush=True)
            print("Original runner exit: " + str(status["runner_exit_code"]), flush=True)
            verify_browser_evidence(output, summary)
            if status["browser_blockers"]:
                print("Browser interactions blocked: " + str(len(status["browser_blockers"])) +
                      "; inspect screenshot timelines and execution.json", flush=True)
                exit_code = exit_code or 2
            if summary["plans"] != 3 or summary["not_run"] or summary["module_instances"] != 71:
                raise Blocker("incomplete official plan evidence; inspect summary.json")
            suite_check(suite)
            # Outcomes, terminal status, completeness and the original runner status
            # must agree. A timeout after the last result is still an interruption.
            status["all_passed"] = fully_passed(summary, status)
    except (Exception, KeyboardInterrupt) as error:
        status["state"] = "BLOCKED" if status["runner_exit_code"] is None else "EVIDENCE_ERROR"
        status["blocker"] = str(error) if isinstance(error, Blocker) else type(error).__name__ + "; inspect harness.private.log"
        private_write(output / "harness.private.log", traceback.format_exc())
        print(status["blocker"], file=sys.stderr)
        if isinstance(error, PreparationRequired):
            status["next_steps"] = ["make oidc-conformance-prepare", "make oidc-conformance-test"]
            status["setup_note"] = (
                "Run these commands from the repository root. Preparation downloads and builds the local suite prerequisites. "
                "If you supplied custom prerequisite paths, correct them or remove those overrides when retrying. "
                "Use a new CONFORMANCE_RESULTS directory for the retry. "
                "For installation locations and removal instructions, run make oidc-conformance-help.")
            print("\nSETUP REQUIRED — run from the repository root:", file=sys.stderr)
            for step in status["next_steps"]:
                print("  " + step, file=sys.stderr)
            print(status["setup_note"], file=sys.stderr)
        original = status["runner_exit_code"]
        exit_code = (original if original > 0 else 128 - original) if original else 2
    finally:
        exit_code = finish_evidence(output, processes, status, exit_code)
    return exit_code


def finish_evidence(output, processes, status, exit_code):
    processes.close()
    status["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_json(output / "execution.json", status)
    try:
        private_write(output / "index.html", render_report(output))
        print("HTML report: " + str(output / "index.html"), flush=True)
    except Exception as error:
        status.update(state="EVIDENCE_ERROR", all_passed=False,
                      report_error=type(error).__name__ + "; inspect report.private.log")
        private_write(output / "report.private.log", traceback.format_exc())
        write_json(output / "execution.json", status)
        print("HTML report generation failed; inspect private report.private.log", file=sys.stderr)
        # Report failures fail an otherwise successful command, but cannot
        # replace the original nonzero official runner result.
        exit_code = exit_code or 2
    for path in output.rglob("*"):
        if path.is_file():
            os.chmod(path, 0o700 if path == output / "caddy" else 0o600)
        elif path.is_dir():
            os.chmod(path, 0o700)
    write_json(output / "evidence-sha256.json", {str(p.relative_to(output)): digest(p)
               for p in output.rglob("*") if p.is_file() and p.name != "evidence-sha256.json"})
    return exit_code


def main():
    # SIGTERM from CI should follow the same cleanup/evidence path as Ctrl-C.
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    if sys.version_info < (3, 12):
        parser.error("conformance requires Python 3.12+")
    parser.add_argument("--results", type=Path, required=True, help="new directory below this checkout's tmp/")
    parser.add_argument("--local-only", action="store_true", help="opt-in fixture diagnosis only; no Foundation outcome claim")
    parser.add_argument("--suite", type=Path, default=WORK / "suite")
    parser.add_argument("--java", type=Path, default=WORK / "tools/java/bin/java")
    parser.add_argument("--mongod", type=Path, default=WORK / "tools/mongodb/bin/mongod")
    parser.add_argument("--runner-python", type=Path, default=WORK / "venv/bin/python")
    parser.add_argument("--chrome", type=Path, default=chrome_binary(WORK / "tools/chrome"))
    parser.add_argument("--chromedriver", type=Path, default=WORK / "tools/chromedriver/chromedriver")
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    try:
        return run(args)
    except (Blocker, ArtifactError) as error:
        print("Prerequisite blocker: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
