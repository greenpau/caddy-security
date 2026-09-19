"""Opt-in conformance units; intentionally outside regular test discovery."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "assets/scripts"))
SPEC = importlib.util.spec_from_file_location("oidc_conformance", ROOT / "assets/scripts/oidc_conformance.py")
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class ConformanceTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="oidc-conformance-unit-", dir=ROOT / "tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def export(self, filename, identifier, outcome, signature=True):
        with zipfile.ZipFile(self.root / filename, "w") as archive:
            name = "test-log-module-" + identifier
            archive.writestr(name + ".json", json.dumps({
                "testInfo": {"testId": identifier, "testName": "same-module", "result": outcome, "status": "FINISHED"},
                "results": [{"result": outcome, "msg": "observed outcome"}],
            }))
            if signature:
                archive.writestr(name + ".sig", "signature")

    def test_every_nonpass_and_retry_is_preserved(self):
        outcomes = ["PASSED", "WARNING", "SKIPPED", "REVIEW", "FAILED", "INTERRUPTED", "UNKNOWN"]
        for i, outcome in enumerate(outcomes):
            self.export(str(i) + ".zip", str(i), outcome)
        # A plan export and a per-instance export of the same attempt count once.
        self.export("duplicate.zip", "0", "PASSED")
        result = harness.summarize_exports(self.root)
        self.assertEqual(result["counts"], dict.fromkeys(outcomes, 1))
        self.assertEqual(result["module_instances"], 7)
        self.assertEqual(len(result["modules"][4]["nonpass_events"]), 1)

    def test_partial_and_interrupted_results_are_serializable_without_pass_promotion(self):
        self.export('partial.zip', 'partial', None)
        result = harness.summarize_exports(self.root)
        harness.write_json(self.root / 'summary.json', result)
        self.assertEqual(result['counts'], {'UNKNOWN': 1})
        with zipfile.ZipFile(self.root / 'partial.zip', 'w') as archive:
            archive.writestr('partial.json', json.dumps({'testInfo': {'testId': 'partial', 'testName': 'module',
                'result': None, 'status': 'INTERRUPTED'}, 'results': [{'result': 'INTERRUPTED', 'msg': 'cancelled'}]}))
            archive.writestr('partial.sig', 'signature')
        result = harness.summarize_exports(self.root)
        self.assertEqual(result['counts'], {'INTERRUPTED': 1})
        self.assertEqual(result['modules'][0]['result'], 'UNKNOWN')
        self.assertEqual(result['modules'][0]['status'], 'INTERRUPTED')

    def test_missing_signature_corruption_and_conflicting_results_fail(self):
        self.export("a.zip", "a", "PASSED", signature=False)
        with self.assertRaisesRegex(harness.Blocker, "signature"):
            harness.summarize_exports(self.root)
        self.export("a.zip", "a", "PASSED")
        self.export("b.zip", "a", "FAILED")
        with self.assertRaisesRegex(harness.Blocker, "conflicting"):
            harness.summarize_exports(self.root)
        (self.root / "a.zip").write_bytes(b"broken zip")
        with self.assertRaises(zipfile.BadZipFile):
            harness.summarize_exports(self.root)

    def test_interruption_nonterminal_and_incomplete_are_never_all_passed(self):
        summary = {"plans": 3, "not_run": [], "module_instances": 71,
                   "modules": [{"result": "PASSED", "status": "FINISHED"} for _ in range(71)]}
        self.assertTrue(harness.fully_passed(summary, {"runner_exit_code": 0}))
        self.assertFalse(harness.fully_passed(summary, {"runner_exit_code": 1}))
        self.assertFalse(harness.fully_passed(summary, {"runner_exit_code": 0, "interruption": "timeout"}))
        summary["modules"][0]["status"] = "RUNNING"
        self.assertFalse(harness.fully_passed(summary, {"runner_exit_code": 0}))
        summary["modules"][0]["status"] = "FINISHED"
        summary["module_instances"] = 70
        self.assertFalse(harness.fully_passed(summary, {"runner_exit_code": 0}))

    def test_real_runner_nonzero_is_not_converted_to_pass(self):
        processes = harness.Processes(self.root)
        self.addCleanup(processes.close)
        status = {}
        result = harness.run_runner(processes, [sys.executable, "-c", "raise SystemExit(7)"],
                                    self.root, os.environ.copy(), 5, status)
        self.assertEqual((result, status["runner_exit_code"]), (7, 7))

    def test_deadline_stops_and_reaps_owned_runner(self):
        processes = harness.Processes(self.root)
        status = {}
        result = harness.run_runner(processes, [sys.executable, "-c", "import time; time.sleep(60)"],
                                    self.root, os.environ.copy(), 0.1, status)
        processes.close()
        self.assertEqual(status["runner_exit_code"], -signal.SIGTERM)
        self.assertEqual(result, 128 + signal.SIGTERM)
        self.assertEqual(status["interruption"], "TimeoutExpired")
        self.assertTrue(json.loads((self.root / "processes.json").read_text())[0]["reaped"])

    def test_completed_build_launcher_stops_its_compiler_helper(self):
        ready, stopped = self.root / "ready", self.root / "stopped"
        helper = ("import signal,time,pathlib,sys; "
                  f"signal.signal(signal.SIGTERM, lambda *_: (pathlib.Path({str(stopped)!r}).write_text('stopped'), sys.exit(0))); "
                  f"pathlib.Path({str(ready)!r}).touch(); time.sleep(60)")
        launcher = ("import subprocess,time,pathlib; "
                    f"subprocess.Popen([{sys.executable!r}, '-c', {helper!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                    f"\nwhile not pathlib.Path({str(ready)!r}).exists(): time.sleep(0.01)\n")
        harness.command([sys.executable, "-c", launcher], timeout=5)
        deadline = time.monotonic() + 2
        while not stopped.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(stopped.exists(), "compiler helper outlived its owned build group")

    def test_scope_rejects_escape_symlinks_and_overwrite(self):
        with self.assertRaises(harness.Blocker):
            harness.inside_tmp(ROOT / "../go-authcrunch")
        (self.root / "escape").symlink_to(ROOT.parent, target_is_directory=True)
        with self.assertRaises(harness.Blocker):
            harness.inside_tmp(self.root / "escape/result", new=True)
        with self.assertRaises(harness.Blocker):
            harness.inside_tmp(self.root, new=True)
        self.assertEqual(harness.inside_tmp(self.root / "new", new=True), self.root / "new")
        nested = self.root / "new parents" / "run"
        self.assertEqual(harness.inside_tmp(nested, new=True), nested)
        with self.assertRaises(harness.Blocker):
            harness.inside_tmp(self.root / "escape/nonexistent/nested", new=True)

    def test_runner_cannot_inherit_tls_bypass_or_failure_suppression(self):
        with mock.patch.dict(os.environ, {"CONFORMANCE_DEV_MODE": "1", "DISABLE_SSL_VERIFY": "1",
                            "CONFORMANCE_MAX_CONSECUTIVE_FAILURES": "1", "CONFORMANCE_RESTART_RETRIES": "5",
                            "HTTPS_PROXY": "https://unrelated.invalid", "PYTHONPATH": "unrelated"}):
            env = harness.runner_environment("https://localhost:8443", "ca.pem", self.root, "private-token")
        for name in ("CONFORMANCE_DEV_MODE", "DISABLE_SSL_VERIFY", "HTTPS_PROXY", "PYTHONPATH"):
            self.assertNotIn(name, env)
        self.assertEqual(env["SSL_CERT_FILE"], "ca.pem")
        self.assertEqual(env["CONFORMANCE_RESTART_RETRIES"], "0")
        self.assertEqual(env["CONFORMANCE_TOKEN"], "private-token")

    def test_redaction_removes_credentials_without_discarding_settings(self):
        source = {"clients": [{"client_secret": "private", "require_pkce": False}], "password": "private",
                  "issuer": "https://localhost/auth"}
        result = harness.redact(source)
        self.assertNotIn("private", json.dumps(result))
        self.assertFalse(result["clients"][0]["require_pkce"])
        self.assertEqual(result["issuer"], source["issuer"])
        self.assertEqual(source["password"], "private")

    def test_browser_evidence_is_scoped_to_the_requested_page(self):
        issuer, base = "https://op.test/auth", "https://suite.test"
        plan = harness.plan_config({}, issuer, base, "fixture-password")
        for name, expected in {
                "default": None, "oidcc-ensure-request-object-with-redirect-uri": None,
                "oidcc-prompt-login": "real", "oidcc-max-age-1": "real",
                "oidcc-ensure-registered-redirect-uri": "real",
                "oidcc-ensure-redirect-uri-in-authorization-request": "invalid_request",
                "oidcc-redirect-uri-query-added": "invalid_request",
                "oidcc-redirect-uri-query-mismatch": "invalid_request"}.items():
            with self.subTest(module=name):
                browser = plan["override"].get(name, plan)["browser"]
                if expected == "real":
                    self.assertEqual(browser, [])
                    continue
                tasks = browser[0]["tasks"]
                captures = [(task["match"], command) for task in tasks for command in task["commands"]
                            if str(command[-1]).startswith("update-image-placeholder")]
                self.assertEqual(len(captures), int(expected is not None))
                if expected:
                    self.assertEqual(captures[0][1][4], expected)
                    self.assertEqual(captures[0][0], issuer + (
                        "/login*" if expected == "(?i)username" else "/oidc/authorize*"))
                if expected != "invalid_request":
                    # Login and second-client consent still reach real forms.
                    commands = [command for task in tasks for command in task["commands"]]
                    self.assertIn(["text", "name", "secret", "fixture-password"], commands)
                    self.assertIn(["click", "name", "decision"], commands)
                    consent = next(task for task in tasks if ["click", "name", "decision"] in task["commands"])
                    self.assertEqual(consent["match"], issuer + "/oidc/*")
                    self.assertIn(["wait", "id", "submission_complete", 10], commands)

    def test_fixture_profile_preserves_caddy_identity_and_credentials(self):
        original = {"users": [{"username": "conformance", "id": "immutable-id", "passwords": ["hash"]},
                              {"username": "unrelated"}], "revision": 4}
        harness.write_json(self.root / "users.json", original)
        harness.seed_profile(self.root)
        result = json.loads((self.root / "users.json").read_text())
        profile = result["users"][0].pop("profile")
        self.assertEqual(result, original)
        self.assertEqual(profile["address"]["country"], "US")
        self.assertIs(profile["phone_number_verified"], False)
        self.assertEqual((self.root / "users.json").stat().st_mode & 0o777, 0o600)
        for users in ([], [{"username": "conformance"}, {"username": "conformance"}]):
            harness.write_json(self.root / "users.json", {"users": users})
            with self.assertRaisesRegex(harness.Blocker, "unique conformance identity"):
                harness.seed_profile(self.root)

    def test_static_registrations_allow_supported_optional_scopes(self):
        for method in harness.CLIENTS.values():
            body = harness.registration_body(method, "https://suite.test/test/a/caddy-local/callback")
            self.assertIn("scopes openid profile email address phone offline_access\n", body)
            self.assertIn("require_pkce false\n", body)
            self.assertNotIn("skip_consent", body)

    def test_persisted_registrations_match_the_static_plan_contract(self):
        callback = "https://suite.test/test/a/caddy-local/callback"
        clients = {name: {"client_id": name + "-id", "client_secret": name + "-secret",
                         "token_endpoint_auth_method": method, "redirect_uris": [callback]}
                   for name, method in harness.CLIENTS.items()}
        # False booleans are omitted in the actual persisted Go representation.
        evidence = harness.verify_registrations(clients, callback)
        self.assertEqual(evidence["distinct_client_ids"], 3)
        self.assertEqual(evidence["distinct_client_secrets"], 3)
        for name, client in clients.items():
            self.assertNotIn(client["client_id"], json.dumps(evidence))
            self.assertNotIn(client["client_secret"], json.dumps(evidence))
            client.update(require_pkce=False, skip_consent=False)
        self.assertEqual(harness.verify_registrations(clients, callback), evidence)
        for name in harness.CLIENTS:
            for field, value in (
                    ("client_id", None), ("client_id", ""), ("client_id", 123),
                    ("client_secret", None), ("client_secret", ""), ("client_secret", 123),
                    ("token_endpoint_auth_method", "none"),
                    ("token_endpoint_auth_method", "client_secret_post" if name != "client_secret_post"
                     else "client_secret_basic"),
                    ("redirect_uris", []), ("redirect_uris", [callback + "/"]),
                    ("redirect_uris", [callback, "https://attacker.example/callback"]),
                    ("require_pkce", True), ("require_pkce", "false"),
                    ("skip_consent", True), ("skip_consent", "false")):
                with self.subTest(name=name, field=field, value=value):
                    invalid = json.loads(json.dumps(clients))
                    invalid[name][field] = value
                    with self.assertRaises(harness.Blocker) as caught:
                        harness.verify_registrations(invalid, callback)
                    for client in clients.values():
                        self.assertNotIn(client["client_secret"], str(caught.exception))
        for name in harness.CLIENTS:
            invalid = dict(clients)
            invalid.pop(name)
            with self.assertRaises(harness.Blocker):
                harness.verify_registrations(invalid, callback)
        with self.assertRaises(harness.Blocker):
            harness.verify_registrations(dict(clients, unrelated=clients["client"]), callback)
        for first, second in (("client", "client2"), ("client", "client_secret_post"),
                              ("client2", "client_secret_post")):
            for field in ("client_id", "client_secret"):
                with self.subTest(first=first, second=second, field=field):
                    invalid = json.loads(json.dumps(clients))
                    invalid[second][field] = invalid[first][field]
                    with self.assertRaisesRegex(harness.Blocker, "distinct"):
                        harness.verify_registrations(invalid, callback)

    def test_consent_preflight_preserves_origin_and_rejects_broken_guards(self):
        issuer, callback = "https://op.example/auth", "https://suite.example/callback"
        clients = {name: {"client_id": name, "client_secret": "synthetic"} for name in harness.CLIENTS}
        for defect in (None, "policy", "csp", "null", "https://attacker.example", "csrf"):
            with self.subTest(defect=defect):
                state, probes = {}, []

                def request(url, data=None, headers=None, method=None):
                    path = harness.urllib.parse.urlsplit(url).path
                    if path.endswith("/authorize"):
                        state.update(harness.urllib.parse.parse_qs(harness.urllib.parse.urlsplit(url).query))
                        state["exchanges"] = 0
                        return 302, {"Location": issuer + "/login"}, b""
                    if path.endswith("/login") or "/sandbox/" in path:
                        if data is None:
                            return 200, {}, b""
                        target = "/sandbox/password" if path.endswith("/login") else "/oidc/continue"
                        return 303, {"Location": issuer + target}, b""
                    if path.endswith("/continue"):
                        if data is None:
                            return 200, {
                                "Referrer-Policy": "no-referrer" if defect == "policy" else "same-origin",
                                "Content-Security-Policy": "form-action *" if defect == "csp" else
                                    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://suite.example",
                            }, (
                                f'<form action="{issuer}/oidc/continue"><input type="hidden" name="csrf" value="real">'
                                '<button name="decision" value="allow">Allow</button></form>').encode()
                        origin = headers["Origin"]
                        probes.append((origin, data["csrf"]))
                        invalid = origin != "https://op.example" or data["csrf"] != "real"
                        if invalid:
                            broken = defect == origin or (defect == "csrf" and data["csrf"] == "forged")
                            return (200 if broken else 403), {}, b""
                        query = harness.urllib.parse.urlencode({"state": state["state"][0], "iss": issuer, "code": "code"})
                        return 302, {"Location": callback + "?" + query}, b""
                    if path.endswith("/token"):
                        state["exchanges"] += 1
                        return (200 if state["exchanges"] == 1 else 400), {}, b'{"id_token":"token"}'
                    self.fail("unexpected preflight URL")

                with mock.patch.object(harness, "Browser") as browser:
                    browser.return_value.request.side_effect = request
                    if defect:
                        with self.assertRaises(harness.Blocker):
                            harness.smoke(self.root, "ca", issuer, callback, clients, "password")
                    else:
                        harness.smoke(self.root, "ca", issuer, callback, clients, "password")
                        self.assertEqual(len(probes), 12)
                        self.assertEqual(probes[-1], ("https://op.example", "real"))
                        evidence = json.loads((self.root / "local-e2e.json").read_text())
                        self.assertEqual(len(evidence), 3)
                        self.assertTrue(all(row["null_origin_rejected"] and row["forged_csrf_rejected"] for row in evidence))

    def test_themed_consent_policy_keeps_nonce_assets_and_callback_restricted(self):
        base = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://suite.example"
        themed = base + "; style-src 'self' 'nonce-abcdefghijklmnopqrstuvwxyz'; img-src 'self'; font-src 'self'"
        for policy in (base, themed):
            harness.validate_consent_policy({"Referrer-Policy": "same-origin", "Content-Security-Policy": policy},
                                            "https://suite.example/callback")
        for policy in (themed + "; script-src 'unsafe-inline'", themed + "; form-action *",
                       themed.replace("img-src 'self'", "img-src *"), themed.replace("font-src 'self'", "font-src https://other.example"),
                       themed.replace("'nonce-abcdefghijklmnopqrstuvwxyz'", "'unsafe-inline'"),
                       themed.replace("frame-ancestors 'none'", "frame-ancestors 'self'"),
                       themed.replace("https://suite.example", "https://attacker.example"),
                       themed.replace("'nonce-abcdefghijklmnopqrstuvwxyz'", "'nonce-short'"), ""):
            with self.subTest(policy=policy), self.assertRaises(harness.Blocker):
                harness.validate_consent_policy({"Referrer-Policy": "same-origin", "Content-Security-Policy": policy},
                                                "https://suite.example/callback")

    def test_real_export_signature_and_tampering(self):
        key = self.root / "key.pem"
        harness.command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key])
        modulus = harness.command(["openssl", "rsa", "-in", key, "-noout", "-modulus"]).stdout.decode().strip().split("=", 1)[1]
        encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
        jwks = {"keys": [{"kty": "RSA", "n": encode(bytes.fromhex(modulus)), "e": "AQAB"}]}
        message = self.root / "message"
        message.write_bytes(b'{"original":"suite result"}')
        signature = harness.command(["openssl", "dgst", "-sha256", "-sign", key, message]).stdout
        def archive(data):
            with zipfile.ZipFile(self.root / "result.zip", "w") as archive:
                archive.writestr("module.json", data)
                archive.writestr("module.sig", encode(signature))
        archive(message.read_bytes())
        self.assertEqual(harness.verify_exports(self.root, jwks), 1)
        archive(b'{"modified":"suite result"}')
        with self.assertRaisesRegex(harness.Blocker, "invalid official export signature"):
            harness.verify_exports(self.root, jwks)


if __name__ == "__main__":
    unittest.main()
