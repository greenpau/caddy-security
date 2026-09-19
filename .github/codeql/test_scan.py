"""Exercise real scans, approved suppressions, and retained neighboring alerts."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[2]
FIXTURES = {
    "go": {"fixture.go": '''package fixture

import (
    "database/sql"
    "log"
    "net/http"
    "os"

    "go.uber.org/zap"
)

func getPassword() string { return os.Getenv("SYNTHETIC_PASSWORD") }

func diagnostics(logger *zap.Logger) {
    password := getPassword()
    logger.Debug("diagnostic", zap.String("password", password)) // alert: go/clear-text-logging
    logger.Info("diagnostic", zap.String("password", password)) // alert: go/clear-text-logging
    log.Print(password) // alert: go/clear-text-logging
}

func query(db *sql.DB, request *http.Request) {
    db.Query("SELECT name FROM users WHERE name = '" + request.URL.Query().Get("name") + "'") // alert: go/sql-injection
}
'''},
    "javascript-typescript": {"app.js": '''const express = require("express");
const app = express();

app.get("/evaluate", (req, res) => {
    res.send(eval(req.query.expression)); // alert: js/code-injection
});
'''},
    "python": {"app.py": '''from flask import Flask, request

app = Flask(__name__)

@app.route("/evaluate")
def evaluate():
    return str(eval(request.args.get("expression"))) # alert: py/code-injection
'''},
    "actions": {".github/workflows/fixture.yml": '''name: Injection fixture
on: issues
permissions:
  contents: write
jobs:
  fixture:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}" # alert: actions/code-injection/critical
      - uses: contributor-assistant/github-action@v2.3.1 # extended-alert: actions/unpinned-tag
'''},
}

CACHE_FIXTURE = '''package fixture

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "path/filepath"
)

type localConfig struct { BaseURL, Realm, Username, APIKey, AccessTokenName string }

func cacheName(cfg localConfig, configPath string) string {
    tokenPath := ""
    if tokenPath == "" {
        identity, _ := json.Marshal([]string{cfg.BaseURL, cfg.Realm, cfg.Username, cfg.APIKey, cfg.AccessTokenName})
        tokenPath = filepath.Join(filepath.Dir(configPath), ".security-tokens", fmt.Sprintf("%x.json", sha256.Sum256(identity)))
    }
    return tokenPath
}

func passwordHash(password string) [32]byte {
    return sha256.Sum256([]byte(password)) // alert: go/weak-sensitive-data-hashing
}
'''


def exception_fixtures(language):
    if language == "go":
        return {"command_local_client.go": CACHE_FIXTURE,
                "neighbor/command_local_client.go": CACHE_FIXTURE}
    if language == "python":
        source = (REPO / "assets/scripts/oidc_conformance.py").read_text()
        neighbor = source.replace("stream.write(data)",
                                  "stream.write(data) # alert: py/clear-text-storage-sensitive-data")
        browser_path = "assets/scripts/oidc_certification_conformance_tests/test_oidc_conformance_browser.py"
        browser = (REPO / browser_path).read_text()
        browser_neighbor = browser.replace(
            "server.socket = context.wrap_socket(server.socket, server_side=True)",
            "server.socket = context.wrap_socket(server.socket, server_side=True) # alert: py/insecure-protocol")
        return {"assets/scripts/oidc_conformance.py": source + '''

def store_production_password(password):
    with open("production.txt", "w") as output:
        output.write(password) # alert: py/clear-text-storage-sensitive-data
''', "assets/scripts/unapproved_conformance.py": neighbor,
                browser_path: browser + '''

def unapproved_tls_server(sock):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    return context.wrap_socket(sock, server_side=True) # alert: py/insecure-protocol
''', "assets/scripts/oidc_certification_conformance_tests/unapproved_browser.py": browser_neighbor}
    if language == "javascript-typescript":
        source = (REPO / "testdata/browser/token_refresh_browser_e2e.cjs").read_text()
        neighbor = source.replace('if (message.method === "Page.frameNavigated") {',
                                  'if (message.method === "Page.frameNavigated") { // extended-alert: js/user-controlled-bypass')
        neighbor = neighbor.replace('socket.send(JSON.stringify({ id, method, params, sessionId }));',
                                    'socket.send(JSON.stringify({ id, method, params, sessionId })); // extended-alert: js/file-access-to-http')
        return {"testdata/browser/token_refresh_browser_e2e.cjs": source,
                "testdata/browser/unapproved_token_refresh_browser_e2e.cjs": neighbor}
    return {}


def run(args, root, env=None):
    subprocess.run(args, cwd=root, env=env, check=True, timeout=1200)


def evidence(path):
    sarif = json.loads(path.read_text())
    rules, alerts = set(), set()
    if not sarif.get("runs"):
        raise AssertionError(f"No SARIF runs: {path}")
    for scan in sarif["runs"]:
        for invocation in scan.get("invocations", []):
            if not invocation.get("executionSuccessful", False):
                raise AssertionError(f"Unsuccessful analysis: {path}")
        driver = scan["tool"]["driver"]
        for component in [driver, *scan["tool"].get("extensions", [])]:
            rules.update(rule["id"] for rule in component.get("rules", []))
        for result in scan.get("results", []):
            if result.get("suppressions"):
                raise AssertionError(f"Unexpected suppressed fixture result: {result}")
            for location in result.get("locations", []):
                physical = location["physicalLocation"]
                alerts.add((result["ruleId"], physical["artifactLocation"]["uri"],
                            physical["region"]["startLine"]))
    return rules, alerts


def verify_filter(raw_path, reviewed_path, expected_ids):
    raw, reviewed = evidence(raw_path), evidence(reviewed_path)
    audit = json.loads(reviewed_path.with_suffix(".suppressions.json").read_text())
    if {match["review_id"] for match in audit["matches"]} != expected_ids:
        raise AssertionError(f"Expected approved suppressions {expected_ids}; received {audit}")
    removed = set()
    for match in audit["matches"]:
        location = match["locations"][0]["physicalLocation"]
        removed.add((match["rule_id"], location["artifactLocation"]["uri"], location["region"]["startLine"]))
    if reviewed[0] != raw[0] or reviewed[1] != raw[1] - removed:
        raise AssertionError("Filtering changed unrelated rules or findings")
    return reviewed


def main():
    language = os.environ.get("CODEQL_LANGUAGE", "go")
    if language not in FIXTURES:
        raise SystemExit("CODEQL_LANGUAGE must be go, javascript-typescript, python or actions")
    pack_language = "javascript" if language == "javascript-typescript" else language
    executable = shutil.which(os.environ.get("CODEQL", "codeql"))
    if not executable:
        raise SystemExit("CodeQL CLI is required; set CODEQL to its executable path.")
    codeql = str(Path(executable).resolve())
    coverage = (REPO / ".coverage/codeql").resolve()
    if REPO not in coverage.parents:
        raise SystemExit("CodeQL fixture output must stay inside this checkout")
    coverage.mkdir(parents=True, exist_ok=True)
    # Preserve successful and failed fixtures and their original scan evidence.
    root = Path(tempfile.mkdtemp(prefix=f"{language}-e2e-", dir=coverage))
    print(f"CodeQL regression fixture: {root}", flush=True)
    for name in ("assets/scripts/run_codeql_scan.sh", "assets/scripts/filter_codeql_results.py",
                 ".github/codeql/codeql-config.yml", ".github/codeql/suppressions.json"):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / name, destination)
    fixtures = {**FIXTURES[language], **exception_fixtures(language)}
    for name, source in fixtures.items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    if language == "go":
        module = (REPO / "go.mod").read_text()
        zap_version = re.search(r"go\.uber\.org/zap (v\S+)", module).group(1)
        go_version = re.search(r"(?m)^go (\S+)", module).group(1)
        (root / "go.mod").write_text(
            f"module codeql-fixture.invalid/scan\n\ngo {go_version}\n\n"
            f"require go.uber.org/zap {zap_version}\n")
        run(["go", "mod", "tidy"], root)
        run(["gofmt", "-w", *(name for name in fixtures if name.endswith(".go"))], root)
    expected, extended_expected = set(), set()
    for name in fixtures:
        for line, value in enumerate((root / name).read_text().splitlines(), 1):
            if "extended-alert: " in value:
                extended_expected.add((value.split("extended-alert: ", 1)[1].strip(), name, line))
            elif "alert: " in value:
                expected.add((value.split("alert: ", 1)[1].strip(), name, line))
    if language == "go":
        # The exact approved cache expression must also remain visible in another file.
        path = "neighbor/command_local_client.go"
        line = next(i for i, value in enumerate((root / path).read_text().splitlines(), 1)
                    if 'fmt.Sprintf("%x.json"' in value)
        expected.add(("go/weak-sensitive-data-hashing", path, line))
    output = root / ".coverage/scan"
    env = {**os.environ, "PYTHON": sys.executable, "CODEQL": codeql, "CODEQL_LANGUAGE": language,
           "CODEQL_OUTPUT_DIR": str(output)}
    run(["bash", "assets/scripts/run_codeql_scan.sh"], root, env)
    approved = {"go": {"CQ-001"}, "python": {"CQ-002", "CQ-006"}}.get(language, set())
    configured = verify_filter(output / "raw/results.sarif", output / "results.sarif", approved)
    if not expected <= configured[1]:
        raise AssertionError(f"Missing alerts: {expected - configured[1]}; received: {configured[1]}")
    run([codeql, "database", "analyze", str(output / "database"),
         f"codeql/{pack_language}-queries", "--threads=2", "--ram=5922", "--format=sarif-latest",
         f"--output={output / 'upstream.sarif'}"], root)
    baseline = evidence(output / "upstream.sarif")
    if evidence(output / "raw/results.sarif") != baseline:
        raise AssertionError("Raw scan must retain all default rules and fixture alerts")
    extended = output / "raw/security-extended.sarif"
    run([codeql, "database", "analyze", str(output / "database"),
         f"codeql/{pack_language}-queries:codeql-suites/{pack_language}-security-extended.qls",
         "--threads=2", "--ram=5922", "--format=sarif-latest", f"--output={extended}"], root)
    run([sys.executable, "assets/scripts/filter_codeql_results.py", "--input", str(extended),
         "--output-dir", str(output)], root)
    if language == "javascript-typescript":
        approved = {"CQ-004", "CQ-005"}
    reviewed = verify_filter(extended, output / "security-extended.sarif", approved)
    if not expected | extended_expected <= reviewed[1]:
        raise AssertionError(f"Extended scan lost retained findings: {(expected | extended_expected) - reviewed[1]}")
    print(f"PASS: {language}: approved exceptions verified; {len(expected)} default and "
          f"{len(extended_expected)} additional extended fixture alerts retained; all "
          f"{len(configured[0])} default and {len(reviewed[0])} extended rule IDs retained.")


if __name__ == "__main__":
    main()
