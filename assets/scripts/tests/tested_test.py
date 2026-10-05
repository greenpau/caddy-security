"""Verify Make preserves failures, fresh evidence, and independent report bundles."""

import json
import os
import re
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
(ROOT / 'tmp').mkdir(exist_ok=True)


class TestedLifecycleTests(unittest.TestCase):
    def test_success_filter_failure_and_build_failure_keep_honest_reports(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tmp', prefix='_caddy-security-tested-') as directory:
            root = Path(directory)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('GIT_', 'TEST_')) and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}
            env.pop('TEST_TIMEOUT', None)
            env.update(PYTHONDONTWRITEBYTECODE='1', TEST='.', TEST_DIR='./...',
                       COVERAGE_DIR='.coverage', MINIMUM_COVERAGE='1')
            shutil.copyfile(ROOT / 'Makefile', root / 'Makefile')
            (root / 'assets/scripts').mkdir(parents=True)
            shutil.copyfile(ROOT / 'assets/scripts/test_guard.py', root / 'assets/scripts/test_guard.py')
            (root / 'VERSION').write_text('1.0.0\n')
            pinned = re.search(r'github.com/greenpau/tested (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
            (root / 'go.mod').write_text('module example.invalid/testedfixture\n\ngo 1.25.0\n\n'
                                        f'require github.com/greenpau/tested {pinned}\n\n'
                                        'tool github.com/greenpau/tested\n')
            (root / 'go.sum').write_text(''.join(line for line in (ROOT / 'go.sum').read_text().splitlines(True)
                                              if line.startswith('github.com/greenpau/tested ')))
            (root / 'fixture.go').write_text('package fixture\nfunc Value() int { return 42 }\n')
            test = root / 'fixture_test.go'
            test.write_text('package fixture\nimport ("os"; "testing"; "time")\n'
                            'func TestSelected(t *testing.T) {\n'
                            'if gate := os.Getenv("TESTED_STREAM_GATE"); gate != "" {\n'
                            't.Log("streaming fixture ready")\n'
                            'deadline := time.Now().Add(20*time.Second)\n'
                            'for { if _, err := os.Stat(gate); err == nil { break }; '
                            'if time.Now().After(deadline) { t.Fatal("live output was not forwarded") }; '
                            'time.Sleep(10*time.Millisecond) }\n}\n'
                            'if Value()!=42 { t.Fatal("value") } }\n'
                            'func TestExcluded(t *testing.T) { t.Fatal("must be filtered out") }\n')
            subprocess.run(['git', 'init', '-q', '-b', 'main'], cwd=root, env=env, check=True)
            source = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}

            def make(*arguments):
                return subprocess.run(['make', *arguments], cwd=root, env=env, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)

            def bundle(directory):
                return {path.relative_to(directory): path.read_bytes()
                        for path in directory.rglob('*') if path.is_file()}

            report = root / '.coverage'
            report.mkdir()
            notes = report / 'notes.txt'
            notes.write_text('Keep investigation notes across test runs.\n')
            # The Go test cannot finish until its log crosses tested, the guard,
            # and Make. A final buffered summary cannot satisfy this handshake.
            gate = root / 'stream-release'
            env['TESTED_STREAM_GATE'] = str(gate)
            process = subprocess.Popen(['make', 'test', 'TEST=^TestSelected$'], cwd=root,
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = bytearray()
            try:
                deadline = time.monotonic() + 120
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while b'streaming fixture ready' not in output:
                        remaining = deadline - time.monotonic()
                        self.assertGreater(remaining, 0, output.decode())
                        self.assertTrue(selector.select(remaining), output.decode())
                        chunk = os.read(process.stdout.fileno(), 4096)
                        self.assertTrue(chunk, output.decode())
                        output.extend(chunk)
                self.assertIsNone(process.poll(), output.decode())
                self.assertFalse(gate.exists())
                gate.touch()
                tail, _ = process.communicate(timeout=60)
                result = subprocess.CompletedProcess(process.args, process.returncode,
                                                     (output + tail).decode())
            finally:
                env.pop('TESTED_STREAM_GATE')
                gate.touch()
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=10)
                process.stdout.close()
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(notes.read_text(), 'Keep investigation notes across test runs.\n')
            for name in ('index.html', 'test_output.html', 'coverage.html', 'coverage.out',
                         'summary.json', 'junit.xml', 'test_output.jsonl', 'stderr.log',
                         'run.json', 'manifest.json'):
                self.assertTrue((report / name).is_file(), name)
            for name, content in source.items():
                self.assertEqual((root / name).read_bytes(), content, name)
            first_run = json.loads((report / 'run.json').read_text())
            command = first_run['command']
            self.assertEqual(command[command.index('-timeout') + 1], '45m')
            first_profile = (report / 'coverage.out').read_bytes()
            self.assertIn('TestSelected', (report / 'test_output.jsonl').read_text())
            self.assertNotIn('TestExcluded', (report / 'test_output.jsonl').read_text())
            first_bundle = bundle(report)
            # Exercise the recursive target with a real overridden deadline.
            quick = make('qtest', 'QUICK_TEST_DIR=.', 'TEST=^TestSelected$', 'TEST_TIMEOUT=1m')
            self.assertEqual(quick.returncode, 0, quick.stdout)
            self.assertTrue((report / 'quick/manifest.json').is_file())
            quick_command = json.loads((report / 'quick/run.json').read_text())['command']
            self.assertEqual(quick_command[quick_command.index('-timeout') + 1], '1m')
            for name, content in first_bundle.items():
                self.assertEqual((report / name).read_bytes(), content, str(name))
            quick_bundle = bundle(report / 'quick')
            combined_bundle = bundle(report)

            custom = make('test', 'TEST=^TestSelected$', 'COVERAGE_DIR=custom-reports')
            self.assertEqual(custom.returncode, 0, custom.stdout)
            self.assertTrue((root / 'custom-reports/manifest.json').is_file())
            custom_bundle = bundle(root / 'custom-reports')
            self.assertEqual(bundle(report), combined_bundle)

            result = make('test')
            self.assertNotEqual(result.returncode, 0, result.stdout)
            events = [json.loads(line) for line in (report / 'test_output.jsonl').read_text().splitlines()]
            self.assertTrue(any(e.get('Action') == 'fail' and e.get('Test') == 'TestExcluded' for e in events))
            self.assertNotEqual(json.loads((report / 'run.json').read_text()), first_run)
            self.assertNotEqual(make('run-reports').returncode, 0)

            # Keep real timeout failures visible through Make and tested. The
            # fixture finishes in two seconds even if timeout forwarding breaks.
            test.write_text('package fixture\nimport ("testing"; "time")\n'
                            'func TestTimeout(t *testing.T) { Value(); time.Sleep(2*time.Second) }\n')
            # A shell-provided override must reach Go as well as a Make argument.
            env['TEST_TIMEOUT'] = '100ms'
            timed_out = make('test', 'TEST=^TestTimeout$')
            env.pop('TEST_TIMEOUT')
            self.assertNotEqual(timed_out.returncode, 0, timed_out.stdout)
            timeout_run = json.loads((report / 'run.json').read_text())
            timeout_command = timeout_run['command']
            self.assertEqual(timeout_command[timeout_command.index('-timeout') + 1], '100ms')
            self.assertNotEqual(timeout_run['exit_code'], 0)
            self.assertIn('test timed out after', (report / 'test_output.jsonl').read_text())
            self.assertNotEqual(json.loads((report / 'summary.json').read_text())['outcome'], 'passed')
            self.assertNotEqual(make('run-reports').returncode, 0)

            test.write_text('package fixture\nfunc broken(\n')
            result = make('test')
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertTrue((report / 'run.json').is_file())
            # Go 1.26 emits build diagnostics as JSON stdout; earlier Go may use stderr.
            evidence = (report / 'test_output.jsonl').read_text() + (report / 'stderr.log').read_text()
            self.assertIn('fixture_test.go', evidence)
            failed_summary = json.loads((report / 'summary.json').read_text())
            self.assertNotEqual(failed_summary['outcome'], 'passed')
            self.assertNotEqual(json.loads((report / 'run.json').read_text())['exit_code'], 0)
            # A valid empty profile can have fresh HTML even after compilation fails.
            if (report / 'coverage.out').exists():
                self.assertNotEqual((report / 'coverage.out').read_bytes(), first_profile)
                self.assertNotIn('fixture.go', (report / 'coverage.out').read_text())
            self.assertNotIn('TestSelected', (report / 'test_output.jsonl').read_text())
            self.assertEqual(notes.read_text(), 'Keep investigation notes across test runs.\n')
            self.assertEqual(bundle(report / 'quick'), quick_bundle)
            self.assertEqual(bundle(root / 'custom-reports'), custom_bundle)


if __name__ == '__main__':
    unittest.main()
