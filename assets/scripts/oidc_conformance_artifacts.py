"""Ownership, dependency boundaries and locking for private OIDC test artifacts."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


MARKER = "oidc-conformance-run.json"
KIND = "caddy-security-oidc-conformance"
DEPENDENCY_RECORD = "oidc-conformance-dependencies.json"
DEPENDENCIES = ("suite", "tools", "venv", "m2", "pip-cache", "runtime", ".config",
                "prerequisites.json", "suite-build.log", "oidc-conformance.lock", DEPENDENCY_RECORD)


class ArtifactError(RuntimeError):
    """Unsafe or active artifact operation; no deletion should proceed."""


def workspace(root):
    root = Path(root).resolve()
    work = root / "tmp/oidc-conformance"
    if work.resolve() != work:
        raise ArtifactError("OIDC workspace must not use symlinked paths")
    return work


@contextmanager
def workspace_lock(root, operation):
    """Shared runs; exclusive preparation/cleanup. The lock inode is retained."""
    work = workspace(root)
    work.parent.mkdir(exist_ok=True, mode=0o700)
    work.mkdir(exist_ok=True, mode=0o700)
    fd = os.open(work / "oidc-conformance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if operation == "run" else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ArtifactError("OIDC tests, preparation or cleanup are active; wait for them to finish") from error
        yield
    finally:
        os.close(fd)


def dependency_paths(root, args=None):
    paths = [workspace(root) / name for name in DEPENDENCIES]
    record = workspace(root) / DEPENDENCY_RECORD
    if record.exists() or record.is_symlink():
        paths.extend(Path(p).resolve() for p in read_metadata(record)["dependencies"])
    for name in ("suite", "java", "mongod", "runner_python", "chrome", "chromedriver"):
        value = getattr(args, name, None)
        if value is not None:
            path = Path(value)
            if not path.is_absolute():
                path = Path(root) / path
            if name != "suite" and path.parent.name == "bin":
                path = path.parent.parent
            paths.append(path.resolve())
    return paths


def retain_custom_dependencies(root, dependencies):
    """Keep custom tool locations known after their last run bundle is deleted."""
    work = workspace(root)
    defaults = [work / name for name in DEPENDENCIES]
    custom = sorted({str(p) for p in dependencies if not any(p.is_relative_to(d) for d in defaults)})
    if not custom:
        return
    data = {"kind": KIND, "version": 1, "dependencies": custom}
    record = work / DEPENDENCY_RECORD
    if record.exists() and read_metadata(record) == data:
        return
    fd, name = tempfile.mkstemp(prefix=".oidc-conformance-dependencies-", dir=work)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        temporary.replace(record)
    finally:
        temporary.unlink(missing_ok=True)


def intersects(first, second):
    return first.is_relative_to(second) or second.is_relative_to(first)


def validate_output(root, output, dependencies):
    tmp = Path(root).resolve() / "tmp"
    if output.resolve() != output or output == tmp or not output.is_relative_to(tmp):
        raise ArtifactError("OIDC artifacts must be a real directory below this checkout's tmp/")
    if any(intersects(output, path) for path in dependencies):
        raise ArtifactError("OIDC artifacts overlap retained prerequisites: " + str(output))


def mark_output(root, output, args):
    dependencies = dependency_paths(root, args)
    validate_output(root, output, dependencies)
    for parent in output.parents:
        if parent == Path(root).resolve() / "tmp":
            break
        if run_metadata(parent) is not None:
            raise ArtifactError("OIDC result directories must not be nested in an earlier run")
    output.mkdir(parents=True, mode=0o700)
    with (output / MARKER).open("x") as stream:
        os.chmod(stream.name, 0o600)
        json.dump({"kind": KIND, "version": 1, "dependencies": [str(p) for p in dependencies]}, stream, indent=2)
        stream.write("\n")


def read_metadata(marker):
    if marker.is_symlink():
        raise ArtifactError("symlinked OIDC artifact metadata: " + str(marker))
    try:
        data = json.loads(marker.read_text())
        if data["kind"] == KIND and data["version"] == 1 and isinstance(data["dependencies"], list):
            if all(isinstance(p, str) and Path(p).is_absolute() for p in data["dependencies"]):
                return data
    except (ValueError, KeyError, TypeError):
        pass
    raise ArtifactError("invalid OIDC artifact metadata: " + str(marker))


def run_metadata(path):
    marker = path / MARKER
    if marker.exists() or marker.is_symlink():
        return read_metadata(marker)
    # Recognize pre-cleanup harness bundles, including blocked and local-only runs.
    legacy = path / "execution.json"
    if legacy.is_file() and not legacy.is_symlink():
        try:
            data = json.loads(legacy.read_text())
            if (isinstance(data, dict) and data.get("certification") is False
                    and isinstance(data.get("local_only"), bool)
                    and re.fullmatch(r"[0-9a-f]{40}", data.get("suite_revision", ""))
                    and "started_at" in data and "state" in data and "runner_exit_code" in data):
                return {"dependencies": []}
        except (ValueError, TypeError):
            pass
    return None


def cleanup(root, args=None, dry_run=False):
    """Delete run bundles and supplemental OIDC output, retaining prerequisites."""
    with workspace_lock(root, "cleanup"):
        dependencies = dependency_paths(root, args)
        candidates = []
        tmp = Path(root).resolve() / "tmp"
        for directory, names, _ in os.walk(tmp, followlinks=False):
            path = Path(directory)
            names[:] = [n for n in names if not (path / n).is_symlink()
                        and not any((path / n).is_relative_to(p) for p in dependencies)]
            metadata = run_metadata(path)
            if metadata is not None:
                candidates.append(path)
                dependencies.extend(Path(p).resolve() for p in metadata["dependencies"])
                names[:] = []
        # Supplemental diagnostics predate bundle ownership metadata. Reserve
        # these names only directly under tmp/, never anywhere in source or in
        # dependencies. Collect bundle metadata first so custom tools survive.
        supplemental = []
        for path in tmp.iterdir():
            if path == workspace(root) or path.is_symlink():
                continue
            if not (path.name.startswith("oidc-") or path.match("audit_oidc_*.py")
                    or path.match("check_oidc_*.py")):
                continue
            if any(path.is_relative_to(p) for p in dependencies):
                continue
            if path.is_file() or path.is_dir():
                supplemental.append(path)
        # A named supplemental directory can contain a custom result bundle.
        # Remove its parent once, after checking all recorded dependencies.
        candidates = [p for p in candidates if not any(p.is_relative_to(s) for s in supplemental)]
        candidates.extend(supplemental)
        # Validate the entire deletion set before removing anything.
        for path in candidates:
            validate_output(root, path, dependencies)
        if candidates:
            result = subprocess.run(["ps", "-Ao", "pid=,command="], capture_output=True, text=True, timeout=10, check=True)
            for line in result.stdout.splitlines():
                pid, _, command = line.strip().partition(" ")
                if pid == str(os.getpid()):
                    continue
                if any(re.search(re.escape(str(path)) + r"(?=/|\s|$|['\"])", command) for path in candidates):
                    raise ArtifactError("OIDC output is still used by process " + pid + "; stop the owned run before cleanup")
        if not dry_run:
            retain_custom_dependencies(root, dependencies)
        for path in sorted(candidates):
            print(("Would remove: " if dry_run else "Removing: ") + str(path), flush=True)
            if not dry_run:
                # rmtree does not follow directory symlinks inside a bundle.
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        print(f"{'Found' if dry_run else 'Removed'} {len(candidates)} OIDC artifact(s); prerequisites retained.")
        return candidates
