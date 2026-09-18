#!/usr/bin/env python3
"""Download verified, pinned local prerequisites and build the unmodified suite."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tarfile
import urllib.request

from oidc_conformance_browser_tools import install_browsers
from oidc_conformance import Blocker, Processes, REVISION, WORK, command, digest, suite_check, write_json
from oidc_conformance_artifacts import ArtifactError, workspace_lock


TEMURIN = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/"
MAVEN = ("https://dlcdn.apache.org/maven/maven-3/3.9.16/binaries/apache-maven-3.9.16-bin.tar.gz",
         "sha512", "831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6")
PACKAGES = {
    ("Darwin", "arm64"): {
        "java": (TEMURIN + "OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz", "sha256",
                 "3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998"),
        "mongodb": ("https://fastdl.mongodb.org/osx/mongodb-macos-arm64-7.0.43.tgz", "sha256",
                    "764137ddb0eada62eee1a23129e8c32cb197eb2d7f64b63cc89a56a96d7e3cc7"),
    },
    ("Linux", "x86_64"): {
        "java": (TEMURIN + "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz", "sha256",
                 "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"),
        "mongodb": ("https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2204-7.0.43.tgz", "sha256",
                    "cba84b47932ebcdd093de37f2fdbbbd415116d21187ccf9117568726859d6f81"),
    },
}


TOOL_PURPOSES = {
    "java": "Temurin JDK: builds and runs the official Java suite",
    "mongodb": "MongoDB: stores the local suite's test state and results",
    "maven": "Apache Maven: builds the pinned suite jar and downloads its Java dependencies",
}


def installation_help():
    return f"""Local installation root: {WORK}
No system packages or services are installed; no global PATH changes are made.

Paths below that root:
  tools/java       Temurin JDK (Java compiler and runtime)
  tools/mongodb    MongoDB database server for the suite
  tools/maven      Apache Maven suite build tool
  tools/chrome     Pinned Chrome for Testing (headless, no system installation)
  tools/chromedriver  WebDriver controller for screenshots and network events
  tools/           Also contains verified download archives and versioned tool directories;
                   java, mongodb and maven are links to those extracted directories.
  suite/           Pinned OpenID Foundation sources and built jar
  venv/            Isolated Python runner dependencies
  m2/, pip-cache/  Local Maven and Python download caches
  runtime/, .config/  Local preparation temporary files and tool settings

Run from the repository root:
  make oidc-conformance-prepare
  make oidc-conformance-test

Remove all completed OIDC run output, keeping these prerequisites for reuse:
  make oidc-conformance-cleanup

Cleanup finds default and custom result bundles below this checkout's tmp/.
It removes their reports, exports, logs, keys, browser profiles and MongoDB data.
It also removes top-level tmp/oidc-* supplemental outputs (logs, audits, browser
reports), tmp/audit_oidc_*.py and tmp/check_oidc_*.py helpers. The prepared
tmp/oidc-conformance workspace and registered prerequisite locations are retained.
Active runs/preparation block cleanup. Unrelated temporary files are preserved.
Preview all identified artifacts without deleting them:
  python3 assets/scripts/cleanup_oidc_conformance.py --dry-run

After all preparation and test processes have finished, remove the downloaded
prerequisites with the following command (run from the repository root):
  rm -rf tmp/oidc-conformance/tools tmp/oidc-conformance/suite \\
    tmp/oidc-conformance/venv tmp/oidc-conformance/m2 \\
    tmp/oidc-conformance/pip-cache tmp/oidc-conformance/runtime \\
    tmp/oidc-conformance/.config

This leaves run-* evidence bundles, preparation logs and the checksum receipt.
Keep custom CONFORMANCE_RESULTS directories separate from the prerequisite
directories above. Removing the entire tmp/oidc-conformance directory would
also delete any evidence stored there; archive evidence before doing that.
Custom artifact destinations elsewhere under tmp/ are separate.
Rerun make oidc-conformance-prepare before testing again after removal.
"""


def install(name, package):
    url, algorithm, checksum = package
    archive = WORK / "tools" / (name + "-download.tar.gz")
    if not archive.exists():
        with urllib.request.urlopen(url, timeout=120) as source, archive.open("xb") as target:
            import shutil
            shutil.copyfileobj(source, target)
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != checksum:
        raise Blocker("checksum mismatch for " + name + "; preserve/remove the incomplete download before retrying")
    with tarfile.open(archive) as source:
        top = source.getmembers()[0].name.split("/")[0]
        if not (WORK / "tools" / top).exists():
            source.extractall(WORK / "tools", filter="data")
        else:
            # Never overwrite an installed executable in place (in particular,
            # macOS caches code-signing state by inode). Check it against the
            # verified archive instead of silently trusting an existing tool.
            for member in source.getmembers():
                if member.isfile():
                    path = WORK / "tools" / member.name
                    if not path.resolve().is_relative_to((WORK / "tools").resolve()):
                        raise Blocker("installed tool escaped its private directory")
                    with source.extractfile(member) as expected, path.open("rb") as installed:
                        if hashlib.file_digest(expected, "sha256").digest() != hashlib.file_digest(installed, "sha256").digest():
                            raise Blocker("installed tool differs from verified archive: " + member.name)
    target = WORK / "tools" / top
    if name == "java" and platform.system() == "Darwin":
        target /= "Contents/Home"
    link = WORK / "tools" / name
    if not link.exists():
        link.symlink_to(target.relative_to(link.parent), target_is_directory=True)
    if link.resolve() != target.resolve():
        raise Blocker("existing tool link differs from the pinned tool: " + name)
    return {"url": url, algorithm: checksum, "archive_sha256": digest(archive)}


def main(argv=None):
    # Let CI cancellation unwind command()/Maven cleanup for owned sessions.
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    parser = argparse.ArgumentParser(description=__doc__, epilog=installation_help(),
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    with workspace_lock(WORK.parents[1], "prepare"):
        return prepare()


def prepare():
    os.umask(0o077)
    if sys.version_info < (3, 12):
        raise Blocker("prepare requires Python 3.12+ for safe archive extraction")
    key = platform.system(), platform.machine()
    if key not in PACKAGES:
        raise Blocker("no automatic tool pins for " + repr(key) + "; use documented manual prerequisite paths")
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    if WORK.resolve() != WORK or (WORK / "tools").is_symlink():
        raise Blocker("preparation paths must not redirect outside this repository")
    (WORK / "tools").mkdir(exist_ok=True, mode=0o700)
    print("Local prerequisites: " + str(WORK), flush=True)
    print("No system installation. Locations and removal: make oidc-conformance-help", flush=True)
    receipt = {"suite_revision": REVISION, "platform": key, "tools": {}}
    for name, package in dict(PACKAGES[key], maven=MAVEN).items():
        print("Preparing " + name + " — " + TOOL_PURPOSES[name], flush=True)
        print("  Local path: " + str(WORK / "tools" / name), flush=True)
        receipt["tools"][name] = install(name, package)
        print("  Installed files: " + str((WORK / "tools" / name).resolve()), flush=True)
    receipt["tools"].update(install_browsers(WORK, command, write_json, digest, Blocker))
    suite = WORK / "suite"
    if not suite.exists():
        command(["git", "init", suite])
        command(["git", "remote", "add", "origin", "https://gitlab.com/openid/conformance-suite.git"], cwd=suite)
        command(["git", "fetch", "--depth", "1", "origin", REVISION], cwd=suite)
        command(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=suite)
    suite_check(suite)
    venv = WORK / "venv"
    if not venv.exists():
        command([sys.executable, "-m", "venv", venv])
    command([venv / "bin/python", "-m", "pip", "install", "--disable-pip-version-check",
             "--cache-dir", WORK / "pip-cache", "-r", Path(__file__).with_name("oidc-conformance-requirements.txt")])
    env = os.environ.copy()
    (WORK / "runtime").mkdir(exist_ok=True, mode=0o700)
    env.update(JAVA_HOME=str(WORK / "tools/java"),
               MAVEN_OPTS="-Duser.home=" + str(WORK) + " -Djava.io.tmpdir=" + str(WORK / "runtime"),
               TMPDIR=str(WORK / "runtime"), PYTHONDONTWRITEBYTECODE="1")
    args = [WORK / "tools/maven/bin/mvn", "-B", "-Dmaven.repo.local=" + str(WORK / "m2"),
            "-Dmaven.test.skip", "-Dpmd.skip", "-Dkotlin.compiler.daemon=false", "package"]
    print("Building the pinned suite; private log: " + str(WORK / "suite-build.log"), flush=True)
    with (WORK / "suite-build.log").open("wb") as log:
        child = subprocess.Popen([str(a) for a in args], cwd=suite, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if child.wait(timeout=900) != 0:
                raise Blocker("suite build failed; inspect private suite-build.log")
        finally:
            Processes.stop(child)
    suite_check(suite)
    receipt.update(jar_sha256=digest(suite / "target/fapi-test-suite.jar"), build_command=[str(a) for a in args])
    write_json(WORK / "prerequisites.json", receipt)
    print("Prepared " + REVISION + "; all suite tools and data are under " + str(WORK))
    print("Next: make oidc-conformance-test")
    print("When finished, see removal instructions: make oidc-conformance-help")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Prerequisite preparation interrupted; owned processes stopped.", file=sys.stderr)
        sys.exit(130)
    except (Blocker, ArtifactError, OSError, subprocess.SubprocessError) as error:
        print("Prerequisite blocker: " + str(error), file=sys.stderr)
        sys.exit(2)
