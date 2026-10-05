"""Bound local tested runs, including compilers, browsers, and report generation.

This is a sampled watchdog on macOS/Linux, not an OS memory reservation. It
never kills editor processes or unrelated applications. All limits are positive.
"""

import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


MIB = 1024 * 1024
POLL_SECONDS = 0.2
HEARTBEAT_SECONDS = 10
CONSOLE_BYTES = 256 * 1024
CONSOLE_WINDOW_SECONDS = 1


def write_message(stream, message):
    """Best-effort diagnostics, including before and after supervision."""
    try:
        fd = stream.fileno()
        was_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            # Avoid Python's text buffer: a later interpreter flush could block
            # after the descriptor's original mode is restored.
            os.write(fd, (message + '\n').encode('utf-8', errors='replace'))
        finally:
            os.set_blocking(fd, was_blocking)
    except OSError:
        # Status files and exit codes remain authoritative when output is lost.
        pass


class ConsoleOutput:
    """Bound output bursts without silencing later tests or guard heartbeats."""

    def __init__(self, fd):
        self.fd = fd
        self.next_window = time.monotonic() + CONSOLE_WINDOW_SECONDS
        self.window_bytes = 0
        self.notified = False
        self.dropped_bytes = 0
        self.pending_notice = b''

    def write(self, block):
        # A stalled terminal must never block resource checks. tested owns the
        # complete evidence; this presentation stream can drop bytes.
        try:
            return os.write(self.fd, block)
        except (BlockingIOError, BrokenPipeError):
            return 0

    def flush_notice(self):
        if self.pending_notice:
            written = self.write(self.pending_notice)
            self.pending_notice = self.pending_notice[written:]

    def progress(self, block):
        self.flush_notice()
        self.write(block)

    def forward(self, block):
        self.flush_notice()
        now = time.monotonic()
        if now >= self.next_window:
            self.next_window = now + CONSOLE_WINDOW_SECONDS
            self.window_bytes = 0
            self.notified = False
        remaining = CONSOLE_BYTES - self.window_bytes
        chunk = block[:remaining]
        self.window_bytes += len(chunk)
        written = self.write(chunk) if chunk else 0
        self.dropped_bytes += len(block) - written
        if len(block) > remaining and not self.notified:
            self.notified = True
            if not self.pending_notice:
                self.pending_notice = (b'\n[test guard] Output rate limit reached; live output resumes '
                                       b'in the next second. Full logs remain in the tested evidence.\n')
            self.flush_notice()


class RUsage(ctypes.Structure):
    """Darwin rusage_info_v0, from sys/resource.h."""

    _fields_ = [('uuid', ctypes.c_byte * 16), ('values', ctypes.c_uint64 * 10)]


def positive(name, default):
    value = os.environ.get(name, str(default))
    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(f'{name} must be a positive integer') from exc
    if number <= 0:
        raise ValueError(f'{name} must be a positive integer')
    return number


def physical_memory():
    if sys.platform == 'darwin':
        return int(subprocess.check_output(['sysctl', '-n', 'hw.memsize'], timeout=5))
    if sys.platform == 'linux':
        return os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    raise ValueError('test resource monitoring requires macOS or Linux')


class MemoryUsage:
    def __init__(self):
        self.libproc = None
        if sys.platform == 'darwin':
            self.libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
            self.libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            self.libproc.proc_pid_rusage.restype = ctypes.c_int

    def bytes(self, pid, rss):
        if self.libproc is not None:
            # rusage_info_v0: UUID followed by user/system time, wakeups,
            # pageins, wired size, resident size, physical footprint, timestamps.
            # Physical footprint includes compressed memory that ps RSS omits.
            usage = RUsage()
            if self.libproc.proc_pid_rusage(pid, 0, ctypes.byref(usage)) == 0:
                return max(rss, usage.values[7])
            error = ctypes.get_errno()
            if error == errno.ESRCH:
                return 0
            raise OSError(error, 'cannot account for test process memory')
        else:
            try:
                for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                    if line.startswith('VmSwap:'):
                        return rss + int(line.split()[1]) * 1024
            except (FileNotFoundError, ProcessLookupError):
                # A process can exit after ps, including between opening and
                # reading its proc status file. Both ENOENT and ESRCH mean gone.
                return 0
        return rss


def check_host_pressure():
    if sys.platform == 'darwin':
        # XNU exposes dispatch flags here: normal=1, warning=2, critical=4.
        level = int(subprocess.check_output(
            ['sysctl', '-n', 'kern.memorystatus_vm_pressure_level'], timeout=5))
        if level not in (1, 2, 4):
            raise RuntimeError('unrecognized macOS memory pressure level')
        if level == 4:
            raise RuntimeError('system memory pressure is critical')
    else:
        fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(fields['MemAvailable'].split()[0])
        total = int(fields['MemTotal'].split()[0])
        if available < max(256 * 1024, total // 10):
            raise RuntimeError('system available memory is below the safety reserve')


def processes():
    result = subprocess.run(['ps', '-axo', 'pid=,ppid=,rss=,lstart='],
                            capture_output=True, text=True, check=True, timeout=5)
    table = {}
    for line in result.stdout.splitlines():
        pid, parent, rss, started = line.strip().split(None, 3)
        table[int(pid)] = (int(parent), int(rss) * 1024, started)
    return table


def descendants(table, leader, known):
    # Remember birth times so reparented/setsid descendants remain owned without
    # mistaking a reused PID for a child. The Popen leader is not reaped here.
    owned = {pid for pid, born in known.items()
             if pid in table and table[pid][2] == born}
    if leader in table:
        owned.add(leader)
    pending = set(table) - owned
    while True:
        found = {pid for pid in pending if table[pid][0] in owned}
        if not found:
            break
        owned.update(found)
        pending.difference_update(found)
    return {pid: table[pid][2] for pid in owned}


def stop_tree(child, known):
    # Freeze before killing so a failing child cannot keep spawning workers while
    # cleanup traverses it. tested creates another process group, so killing only
    # the supervisor's group is insufficient. Never address an editor ancestor.
    for _ in range(2):
        try:
            table = processes()
            leader = child.pid if child.returncode is None else -1
            if leader == -1:
                known.pop(child.pid, None)
            known = descendants(table, leader, known)
        except (OSError, ValueError, subprocess.SubprocessError):
            # Monitoring itself failed. Still stop the unreaped leader and the
            # children observed in the last successful sample.
            if child.returncode is None:
                known[child.pid] = ''
        for pid in known:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
    if child.returncode is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for pid in sorted(known, key=lambda pid: pid == child.pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    child.wait(timeout=5)


def write_status(path, status):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(status, indent=2) + '\n')
    temporary.replace(path)


def check_artifacts(output, artifact_mb):
    size = 0
    for path in output.iterdir():
        try:
            info = path.stat()
        except FileNotFoundError:
            # tested replaces managed files while reports are being rendered.
            continue
        if stat.S_ISREG(info.st_mode):
            size += info.st_size
    if size > artifact_mb * MIB:
        raise RuntimeError(f'test artifacts exceeded {artifact_mb} MiB')


def supervise(command, output, memory_mb, seconds, max_processes, artifact_mb, report=False):
    status_path = output / ('resource-report-usage.json' if report else 'resource-usage.json')
    status = {'status': 'running', 'memory_limit_mib': memory_mb,
              'timeout_seconds': seconds, 'peak_memory_mib': 0,
              'peak_processes': 0, 'reason': ''}
    write_status(status_path, status)
    interrupted = []
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[sig] = signal.signal(sig, lambda number, frame: interrupted.append(number))
    child = None
    known = {}
    started = time.monotonic()
    launcher = os.getppid()
    next_sample = 0
    next_host_check = 0
    next_heartbeat = started + HEARTBEAT_SECONDS
    result = 125
    stdout_fd = sys.stdout.fileno()
    was_blocking = os.get_blocking(stdout_fd)
    os.set_blocking(stdout_fd, False)
    console = ConsoleOutput(stdout_fd)

    try:
        # Record this attempt before preflight so a monitoring failure cannot
        # leave an older successful run eligible for offline reporting.
        usage = MemoryUsage()
        processes()
        usage.bytes(os.getpid(), 0)
        check_host_pressure()
        check_artifacts(output, artifact_mb)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                now = time.monotonic()
                if interrupted:
                    result = 128 + interrupted[0]
                    raise RuntimeError(f'interrupted by signal {interrupted[0]}')
                if os.getppid() != launcher:
                    raise RuntimeError('test launcher exited')
                if now >= next_sample:
                    table = processes()
                    known = descendants(table, child.pid, known)
                    measured = {pid: usage.bytes(pid, table[pid][1]) for pid in known}
                    memory = sum(measured.values())
                    status['peak_memory_mib'] = max(status['peak_memory_mib'], round(memory / MIB, 1))
                    status['peak_processes'] = max(status['peak_processes'], len(known))
                    status['largest_processes'] = [
                        {'pid': pid, 'memory_mib': round(size / MIB, 1)}
                        for pid, size in sorted(measured.items(), key=lambda item: -item[1])[:5]]
                    if memory > memory_mb * MIB:
                        raise RuntimeError(f'test process tree exceeded {memory_mb} MiB memory budget')
                    if len(known) > max_processes:
                        raise RuntimeError(f'test process tree exceeded {max_processes} processes')
                    if now - started > seconds:
                        raise RuntimeError(f'test workflow exceeded {seconds} seconds')
                    check_artifacts(output, artifact_mb)
                    if now >= next_host_check:
                        check_host_pressure()
                        status['elapsed_seconds'] = round(now - started, 2)
                        status['console_dropped_bytes'] = console.dropped_bytes
                        write_status(status_path, status)
                        next_host_check = now + 1
                    if now >= next_heartbeat:
                        console.progress((f'\n[test guard] Elapsed {now - started:.0f}s; '
                                 f'memory {memory / MIB:.0f}/{memory_mb} MiB; '
                                 f'{len(known)} processes\n').encode())
                        next_heartbeat = now + HEARTBEAT_SECONDS
                    next_sample = now + POLL_SECONDS
                for key, _ in selector.select(timeout=max(0, next_sample - time.monotonic())):
                    block = os.read(key.fd, 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    console.forward(block)
                # Account and collect descendants before poll reaps the leader.
                code = child.poll()
                if code is not None:
                    # Short-lived producers can finish between samples. Check
                    # their final artifacts before publishing a passing status.
                    check_artifacts(output, artifact_mb)
                    result = code if code >= 0 else 128 - code
                    status['status'] = 'passed' if result == 0 else 'failed'
                    # Drain only the pipe's bounded existing tail. A descendant
                    # keeping stdout open cannot postpone cleanup indefinitely.
                    drained = 0
                    while selector.get_map() and drained < CONSOLE_BYTES:
                        try:
                            block = os.read(child.stdout.fileno(), 16384)
                        except BlockingIOError:
                            break
                        if not block:
                            break
                        drained += len(block)
                        console.forward(block)
                    break
            # The leader exited; kill only remembered children after verifying
            # their identities. Do not reuse the reaped leader's PID.
            table = processes()
            survivors = {pid: born for pid, born in known.items()
                         if pid != child.pid and pid in table and table[pid][2] == born}
            if survivors:
                # Zombies cannot consume resources and need their OS parent to reap.
                for pid in survivors:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result = 128 + interrupted[0] if interrupted else 125
        status['status'] = 'aborted'
        status['reason'] = str(exc)
        if child is not None:
            stop_tree(child, known)
    finally:
        if child is not None and child.stdout is not None:
            child.stdout.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        status['elapsed_seconds'] = round(time.monotonic() - started, 2)
        status['exit_code'] = result
        status['console_dropped_bytes'] = console.dropped_bytes
        try:
            write_status(status_path, status)
            if status['status'] == 'aborted':
                write_message(sys.stderr, f"\n[test guard] STOPPED: {status['reason']}. Evidence: {output}")
            if console.dropped_bytes:
                console.progress((f'\n[test guard] Omitted {console.dropped_bytes} console bytes; '
                                  'inspect the tested evidence files for full output.\n').encode())
            console.progress((f"[test guard] {status['status']}; peak {status['peak_memory_mib']} MiB, "
                              f"{status['peak_processes']} processes. Resource evidence: {status_path}\n").encode())
        finally:
            # Completion output is best effort too; a full pipe must not hold
            # the checkout lock after cleanup has finished.
            os.set_blocking(stdout_fd, was_blocking)
    return result


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ('run', 'report'):
        raise ValueError('usage: test_guard.py run|report COMMAND [ARG ...]')
    total_mb = physical_memory() // MIB
    memory_mb = positive('TEST_MEMORY_MB', min(3072, max(1, total_mb * 3 // 8)))
    if memory_mb > total_mb // 2:
        raise ValueError('TEST_MEMORY_MB must leave at least half of physical RAM for the system')
    seconds = positive('TEST_WALL_TIMEOUT', 3300)
    max_processes = positive('TEST_MAX_PROCESSES', 128)
    artifact_mb = positive('TEST_ARTIFACT_MB', 256)
    package_parallelism = positive('TEST_PACKAGE_PARALLELISM', 1)
    positive('TEST_PARALLELISM', 2)
    procs = positive('TEST_GOMAXPROCS', 2)
    go_memory = positive('TEST_GO_MEMORY_MB', 512)
    os.environ['GOMAXPROCS'] = str(procs)
    os.environ['GOMEMLIMIT'] = f'{go_memory}MiB'
    # This also bounds nested go build/test commands in executable E2E fixtures.
    os.environ['GOFLAGS'] = (os.environ.get('GOFLAGS', '') +
                            ' -p=' + str(package_parallelism)).strip()
    lock_directory = Path('.coverage')
    lock_directory.mkdir(exist_ok=True)
    with (lock_directory / 'test-resource.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('another guarded test/report run is active in this checkout') from exc
        output = Path(os.environ.get('COVERAGE_DIR', '.coverage'))
        output.mkdir(parents=True, exist_ok=True)
        status_path = output / 'resource-usage.json'
        if sys.argv[1] == 'report' and status_path.exists():
            previous = json.loads(status_path.read_text())
            if previous.get('status') in ('aborted', 'running'):
                raise ValueError('the previous run was interrupted; retain its evidence and rerun tests')
        write_message(sys.stdout, f'[test guard] Budget {memory_mb} MiB; {seconds}s; '
                      f'GOMAXPROCS={procs}; Go memory target {go_memory} MiB; '
                      f'status every {HEARTBEAT_SECONDS}s.')
        return supervise(sys.argv[2:], output, memory_mb, seconds, max_processes,
                         artifact_mb, report=sys.argv[1] == 'report')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        write_message(sys.stderr, f'[test guard] {error}')
        sys.exit(125)
