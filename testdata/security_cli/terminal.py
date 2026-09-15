"""Exercise Caddy CLI secret prompts on a real terminal using only the stdlib."""

import hashlib
import hmac
import json
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

master, slave = pty.openpty()
original = termios.tcgetattr(slave)
process = None
secret = b"Terminal-secret-123"
mode = sys.argv[2]
success = mode in ("success", "unicode", "crlf", "paste", "login", "login-mfa")
interactive_mfa = mode in ("login-mfa", "login-mfa-terminate", "login-totp-timeout")
code = None
if mode == "unicode":
    secret = "Terminal-秘密-é-123".encode()
elif mode in ("invalid-utf8", "login-invalid-utf8"):
    secret = b"Terminal-\xff-secret-123"
elif mode in ("replacement", "login-replacement"):
    secret = "Terminal-\ufffd-secret-123".encode()
try:
    process = subprocess.Popen(
        [sys.argv[1], "-test.run=^TestRegistrationCommandProcess$", "--"] + sys.argv[3:],
        stdin=slave,
        stdout=subprocess.PIPE,
        stderr=slave,
        env=dict(os.environ, SECURITY_REGISTRATION_COMMAND="1"),
    )
    transcript = b""

    def wait_prompt(prompt):
        global transcript
        deadline = time.monotonic() + 10
        while prompt not in transcript:
            if time.monotonic() > deadline or process.poll() is not None:
                raise RuntimeError("secret prompt was not reached")
            if select.select([master], [], [], 0.05)[0]:
                transcript += os.read(master, 4096)
        if termios.tcgetattr(slave)[3] & termios.ECHO:
            raise RuntimeError("secret prompt left terminal echo enabled")

    wait_prompt(b"Password: ")
    if success or mode == "hash-interrupt" or interactive_mfa:
        if mode == "paste":
            os.write(master, b"\x1b[200~" + secret + b"\x1b[201~\n")
        else:
            os.write(master, secret + (b"\r\n" if mode == "crlf" else b"\n"))
        if mode == "hash-interrupt":
            deadline = time.monotonic() + 5
            while not termios.tcgetattr(slave)[3] & termios.ECHO:
                if time.monotonic() > deadline:
                    raise RuntimeError("password read did not finish")
                time.sleep(0.005)
            time.sleep(0.05)
            process.send_signal(signal.SIGINT)
        elif interactive_mfa:
            wait_prompt(b"MFA method (totp or webauthn): ")
            if mode == "login-mfa-terminate":
                process.send_signal(signal.SIGTERM)
            else:
                os.write(master, b"totp\n")
                wait_prompt(b"Authenticator code: ")
                if mode == "login-mfa":
                    # Independent authenticator for the synthetic enrolled user.
                    # AuthCrunch stores raw secret bytes, not base32 OTP-URI text.
                    counter = (int(time.time()) // 30).to_bytes(8, "big")
                    digest = hmac.new(
                        os.environ["SECURITY_LOCAL_TEST_TOTP_SECRET"].encode(),
                        counter,
                        hashlib.sha1,
                    ).digest()
                    offset = digest[-1] & 15
                    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
                    code = f"{number % 1000000:06d}".encode()
                    os.write(master, code + b"\n")
    elif mode == "interrupt":
        process.send_signal(signal.SIGINT)
    elif mode == "keyboard-interrupt":
        os.write(master, secret + b"\x03")
    elif mode == "keyboard-eof":
        os.write(master, b"\x04")
    elif mode in ("invalid-utf8", "replacement", "login-invalid-utf8", "login-replacement"):
        os.write(master, secret + b"\n")
        # Wake a reader that consumed a RuneError but retained the line tail.
        # It must reject the input, never hash a password with bytes omitted.
        time.sleep(0.1)
        if process.poll() is None:
            os.write(master, b"\n")
    elif mode in ("terminate", "login-terminate"):
        process.send_signal(signal.SIGTERM)
    elif mode != "timeout":
        raise RuntimeError("unknown terminal scenario")
    output, _ = process.communicate(timeout=10)
    while select.select([master], [], [], 0.05)[0]:
        transcript += os.read(master, 4096)
    restored = termios.tcgetattr(slave)
    # BSD sets PENDIN when returning to canonical mode after reading input.
    # It describes queued-input processing, not a user terminal setting.
    restored[3] &= ~getattr(termios, "PENDIN", 0)
    expected = list(original)
    expected[3] &= ~getattr(termios, "PENDIN", 0)
    if restored != expected:
        raise RuntimeError("command failed to restore terminal settings")
    if secret in transcript or secret in output:
        raise RuntimeError("command exposed the input password")
    if code is not None and (code in transcript or code in output):
        raise RuntimeError("command exposed the authenticator code")
    if mode in ("login-invalid-utf8", "login-replacement"):
        if b"private config or password file" not in transcript:
            raise RuntimeError("login did not explain safe file input")
    # Literal U+FFFD may be preserved or rejected, but never silently omitted.
    # Go independently verifies the hash if the command accepted this input.
    if mode == "replacement":
        if process.returncode not in (0, 1):
            raise RuntimeError("unexpected replacement-character exit status")
    elif (process.returncode == 0) != success:
        raise RuntimeError("unexpected command exit status")
    print(json.dumps({"output": output.decode()}))
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    termios.tcsetattr(slave, termios.TCSANOW, original)
    os.close(master)
    os.close(slave)
