#!/usr/bin/env python3
"""Manual Actions orchestration and downloadable disposable OP test evidence."""

import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback

from oidc_conformance import ROOT, WORK, REVISION, digest, private_write, write_json
from oidc_conformance_artifacts import ArtifactError, dependency_paths, validate_output
from oidc_conformance_report import CONTEXT, OUTCOMES, STYLE


DEFAULT = ROOT / "tmp/oidc-conformance-ci"
STAGES = ("prepare", "test")


def workspace(path):
    path = Path(os.path.abspath(path))
    validate_output(ROOT, path, dependency_paths(ROOT))
    if path == WORK or path.is_relative_to(WORK):
        raise ValueError("CI workspace must be separate from the prepared suite")
    return path


def read_json(path):
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def initialize(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    (path / "private").mkdir(mode=0o700)
    (path / "artifact").mkdir(mode=0o700)
    # Preserve the report's existing internal paths and restrictive local modes.
    # The CI archive intentionally publishes the disposable test evidence.
    write_json(path / "private/ci.json", {"suite_revision": REVISION})


def stop_group(child):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        child.poll()
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            child.wait(timeout=10)
            return
        except PermissionError:
            # macOS can report EPERM while a just-signaled group is exiting,
            # before waitpid reaps its leader. Keep polling, never infer exit.
            pass
        time.sleep(.1)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=10)


def run_stage(path, name, command, timeout):
    record = {"state": "RUNNING", "exit_code": None, "wrapper_exit_code": None,
              "command": [str(arg) for arg in command], "timed_out": False, "interrupted": False}
    record_path = path / "private" / (name + ".json")
    write_json(record_path, record)
    child, code = None, 2
    try:
        with (path / "private" / (name + ".log")).open("xb") as log:
            child = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            record["pid"] = child.pid
            write_json(record_path, record)
            try:
                child.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                record["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
                record["interrupted"] = isinstance(error, KeyboardInterrupt)
                stop_group(child)
            record["exit_code"] = child.returncode
        code = child.returncode if child.returncode >= 0 else 128 - child.returncode
        if record["timed_out"]:
            code = 124
        if record["interrupted"]:
            code = 130
        record["state"] = "COMPLETE" if code == 0 else "FAILED"
    except OSError:
        record["state"] = "START_FAILED" if child is None else "ERROR"
        private_write(path / "private" / (name + "-error.log"), traceback.format_exc())
        code = 2
    finally:
        if child is not None and child.poll() is None:
            stop_group(child)
        record["wrapper_exit_code"] = code
        write_json(record_path, record)
    print(f"OIDC {name}: {record['state']}; command exit {record['exit_code']}; wrapper exit {code}", flush=True)
    return code


def safe_text(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else "not recorded"


def exit_code(value):
    return value if type(value) is int else None


def public_summary(path):
    """Construct a small public view; never copy arbitrary JSON, logs or pages."""
    evidence = path / "private/evidence"
    execution = read_json(evidence / "execution.json")
    summary = read_json(evidence / "summary.json")
    candidate = read_json(evidence / "candidate.json")
    modules = []
    for module in summary.get("modules", []):
        outcome = module.get("outcome", "UNKNOWN")
        modules.append({
            "name": safe_text(module.get("name"), r"oidcc-[a-z0-9-]+"),
            "outcome": outcome if outcome in OUTCOMES else "UNKNOWN",
            "status": module.get("status") if module.get("status") in ("FINISHED", "INTERRUPTED") else "INCOMPLETE",
        })
    stages = {}
    for name in STAGES:
        stage = read_json(path / "private" / (name + ".json"))
        stages[name] = {"state": safe_text(stage.get("state", "NOT_RUN"), r"RUNNING|COMPLETE|FAILED|START_FAILED|ERROR|NOT_RUN"),
                        "exit_code": exit_code(stage.get("exit_code")),
                        "wrapper_exit_code": exit_code(stage.get("wrapper_exit_code")),
                        "timed_out": stage.get("timed_out") is True,
                        "interrupted": stage.get("interrupted") is True}
    versions = {}
    for name in ("github.com/caddyserver/caddy/v2", "github.com/greenpau/go-authcrunch"):
        dep = candidate.get("dependencies", {}).get(name, {})
        versions[name] = safe_text(dep.get("Version"), r"v[0-9][0-9A-Za-z.+-]*")
    counts = dict(Counter(m["outcome"] for m in modules))
    return {"certification": False, "suite_revision": REVISION, "versions": versions,
            "commit": safe_text(candidate.get("commit"), r"[0-9a-f]{40}"),
            "source_manifest_sha256": safe_text(candidate.get("source_manifest_sha256"), r"[0-9a-f]{64}"),
            "binary_sha256": safe_text(candidate.get("binary_sha256"), r"[0-9a-f]{64}"),
            "runner_exit_code": exit_code(execution.get("runner_exit_code")), "stages": stages,
            "state": safe_text(execution.get("state", "NOT_RUN"),
                               r"NOT_RUN|RUNNING|RUNNER_FINISHED|BLOCKED|EVIDENCE_ERROR|LOCAL_E2E_COMPLETE"),
            "counts": counts, "modules": modules,
            "all_passed": (execution.get("all_passed") is True and counts == {"PASSED": 71}
                           and all(m["status"] == "FINISHED" for m in modules)
                           and execution.get("runner_exit_code") == 0
                           and execution.get("state") == "RUNNER_FINISHED"
                           and not any(execution.get(k) for k in ("blocker", "report_error", "interruption"))),
            "evidence_has_blocker": bool(execution.get("blocker") or execution.get("report_error")
                                         or execution.get("interruption"))}


def archive_evidence(path):
    partial = path / "artifact/evidence.tar.gz.partial"
    destination = path / "artifact/evidence.tar.gz"
    # A failed repack must not upload a stale archive from an earlier attempt.
    destination.unlink(missing_ok=True)
    try:
        # Archive links as links, never read their targets (Chrome can leave
        # profile singleton symlinks). Keep hidden files and original bytes too.
        with tarfile.open(partial, "x:gz", dereference=False) as bundle:
            bundle.add(path / "private", arcname="private")
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)


def render_public(summary, archived, notice):
    esc = lambda value: html.escape(str(value), quote=True)
    if summary["all_passed"]:
        headline = "All recorded modules passed"
    elif summary["state"] == "RUNNER_FINISHED" and len(summary["modules"]) == 71:
        headline = "Plans completed with non-pass results"
    else:
        headline = "Run needs investigation; inspect execution status and full evidence"
    cards = ''.join(f'<div class="card"><strong class="number">{summary["counts"].get(outcome, 0)}</strong>'
                    f'{outcome}</div>' for outcome in OUTCOMES)
    rows = []
    for index, module in enumerate(summary["modules"], 1):
        explanation = CONTEXT.get((module["name"], module["outcome"]), OUTCOMES[module["outcome"]])
        rows.append("<tr>" + "".join("<td>" + esc(v) + "</td>" for v in
                    (index, module["name"], module["outcome"], module["status"], explanation)) + "</tr>")
    archive_link = ('<p><a href="evidence.tar.gz" download>Download complete test evidence</a></p>'
                    if archived else '<p>No complete evidence archive was produced. '
                    '<a href="archive-error.log" download>Packaging diagnostics</a></p>')
    instructions = """umask 077
mkdir extracted
tar -xzf evidence.tar.gz -C extracted
# Open extracted/private/evidence/index.html locally."""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>Caddy OIDC conformance summary</title><style>{STYLE}</style></head><body><main>'
            f'<header><h1>OIDC conformance report</h1><p><strong>{headline}</strong></p>'
            '<p>Manual Caddy deployment rehearsal. '
            'This is not OpenID certification.</p>'
            f'<p class="notice">{esc(notice)}</p><p>Original official runner exit: '
            f'<strong>{esc(summary["runner_exit_code"])}</strong>. '
            'A zero exit does not turn REVIEW, WARNING or SKIPPED into PASSED.</p>'
            f'<div class="cards">{cards}</div><p>'
            '<a href="summary.json" download>Recorded summary</a> · '
            '<a href="sha256.json" download>Artifact hashes</a></p></header>'
            '<section><h2>Full report and visual evidence</h2><p>The archive preserves '
            'the original linked HTML report, Chrome screenshots and developer-tools timelines, '
            'signed exports, test logs/configuration, exact sources and all module outcomes. '
            'Extract it and open private/evidence/index.html. No key or decryption is required. '
            'Credentials and keys in this report belong to the disposable test deployment.</p>' + archive_link +
            f'<pre>{esc(instructions)}</pre><p>If preparation failed, inspect extracted/private/*.log. '
            'No official outcome is claimed for a blocked or incomplete run.</p></section>'
            '<section><h2>Execution and revisions</h2><pre>' + esc(json.dumps(
                {k: v for k, v in summary.items() if k not in ("modules", "counts")}, indent=2)) +
            '</pre></section><section><h2>Every recorded module instance</h2>'
            '<p>Repeated names are separate instances; all attempts remain listed. '
            'Review details and exact plan membership are in the full report.</p>'
            '<div class="scroll"><table><thead><tr><th>#</th><th>Module</th><th>Outcome</th>'
            '<th>Status</th><th>Explanation</th></tr></thead><tbody>' + "".join(rows) +
            '</tbody></table></div></section></main></body></html>')


def package(path):
    code = 0
    notice = "Read each non-pass result and its evidence. The complete disposable test report is downloadable without a key."
    try:
        summary = public_summary(path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        # A killed writer can leave partial JSON. Still archive the exact files
        # and provide an honest report instead of losing the upload altogether.
        summary = {"certification": False, "all_passed": False, "runner_exit_code": None,
                   "counts": {}, "modules": [], "state": "EVIDENCE_ERROR"}
        notice = "Recorded JSON is incomplete or unreadable. Inspect the original evidence archive; no pass is inferred."
        code = 2
    summary["workflow_steps"] = {
        key: safe_text(os.environ.get("OIDC_CI_" + key.upper()), r"success|failure|cancelled|skipped")
        for key in ("initialize", "go", "prerequisites", "prepare", "sandbox", "test")}
    archived = False
    try:
        # Preserve preparation diagnostics without uploading tool/cache trees.
        for name in ("suite-build.log", "prerequisites.json"):
            source = WORK / name
            if source.is_file():
                shutil.copyfile(source, path / "private" / name)
        archive_evidence(path)
        archived = True
    except (OSError, ValueError, tarfile.TarError):
        for name in ("evidence.tar.gz", "evidence.tar.gz.partial"):
            (path / "artifact" / name).unlink(missing_ok=True)
        diagnostic = traceback.format_exc()
        private_write(path / "private/archive-error.log", diagnostic)
        private_write(path / "artifact/archive-error.log", diagnostic)
        notice = "Evidence archive unavailable. Check the workflow step outcomes and packaging diagnostics; no complete archive is claimed."
        code = 2
    summary["evidence_archive"] = "evidence.tar.gz" if archived else None
    summary["packaging_exit_code"] = code
    write_json(path / "artifact/summary.json", summary)
    private_write(path / "artifact/index.html", render_public(summary, archived, notice))
    write_json(path / "artifact/sha256.json", {p.name: digest(p) for p in (path / "artifact").iterdir()
                                             if p.is_file() and p.name != "sha256.json"})
    message = ("OIDC report artifact: open index.html after downloading.\n\n"
               f"Original runner exit: {summary['runner_exit_code']}; outcomes: "
               + json.dumps(summary["counts"], sort_keys=True) + ".\n\n" + notice + "\n")
    print(message)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(message)
    return code


def main():
    os.umask(0o077)
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DEFAULT)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("initialize")
    sub.add_parser("package")
    stage = sub.add_parser("stage")
    stage.add_argument("name", choices=STAGES)
    stage.add_argument("--timeout", type=int, required=True)
    stage.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        path = workspace(args.workspace)
        if args.action == "initialize":
            initialize(path)
        elif args.action == "package":
            if not path.exists():
                initialize(path)
            return package(path)
        else:
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if args.timeout < 1 or not command:
                parser.error("stage needs a positive timeout and command")
            return run_stage(path, args.name, command, args.timeout)
    except (ArtifactError, ValueError, OSError, subprocess.SubprocessError) as error:
        if "path" in locals() and (path / "private").is_dir():
            private_write(path / "private/ci-error.log", traceback.format_exc())
        # No captured command output, arbitrary evidence text or secret values.
        print(str(error) if isinstance(error, ValueError) else
              "OIDC CI prerequisite or packaging failure; inspect the report and workflow stage.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
