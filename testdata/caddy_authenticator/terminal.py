"""Test the installed CLI's hidden prompts, MFA and terminal restoration."""

import hashlib
import hmac
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
mode = sys.argv[2]
password = b"SyntheticPassword42!"
code = None
process = None
try:
    process = subprocess.Popen(
        [sys.argv[1], "--timeout", "2s" if mode in ("timeout", "totp-timeout") else "10s"] + sys.argv[3:],
        stdin=slave, stdout=subprocess.PIPE, stderr=slave,
    )
    transcript = b""

    def wait_prompt(prompt):
        global transcript
        deadline = time.monotonic() + 8
        while prompt not in transcript:
            if time.monotonic() > deadline or process.poll() is not None:
                raise RuntimeError("prompt was not reached")
            if select.select([master], [], [], 0.05)[0]:
                transcript += os.read(master, 4096)
        if termios.tcgetattr(slave)[3] & termios.ECHO:
            raise RuntimeError("secret prompt left echo enabled")

    if mode == "configure":
        wait_prompt(b"Portal URL: ")
        # One paste must remain available across all three setup prompts.
        os.write(master, b"\x1b[200~" + os.environ["AUTHENTICATOR_TEST_URL"].encode() + b"\nlocal\nalice\x1b[201~\n")
    elif mode not in ("default-configure", "default-login"):
        wait_prompt(b"Password: ")
    if mode in ("login", "paste", "totp-interrupt", "totp-timeout"):
        if mode == "paste":
            os.write(master, b"\x1b[200~" + password + b"\x1b[201~\r\n")
        else:
            os.write(master, password + b"\n")
        wait_prompt(b"Authenticator code: ")
        if mode == "totp-interrupt":
            process.send_signal(signal.SIGINT)
        elif mode != "totp-timeout":
            counter = (int(time.time()) // 30).to_bytes(8, "big")
            digest = hmac.new(b"0123456789abcdef0123456789abcdef", counter, hashlib.sha1).digest()
            offset = digest[-1] & 15
            number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
            code = f"{number % 1000000:06d}".encode()
            os.write(master, code + b"\n")
    elif mode == "interrupt":
        process.send_signal(signal.SIGINT)
    elif mode == "terminate":
        process.send_signal(signal.SIGTERM)
    elif mode == "invalid-utf8":
        os.write(master, b"invalid-\xff-secret\n")
    elif mode == "keyboard-interrupt":
        os.write(master, b"\x03")
    elif mode == "eof":
        os.write(master, b"\x04")
    elif mode not in ("timeout", "configure", "default-configure", "default-login"):
        raise RuntimeError("unknown terminal scenario")
    output, _ = process.communicate(timeout=12)
    while select.select([master], [], [], 0.05)[0]:
        transcript += os.read(master, 4096)
    if mode in ("default-configure", "default-login"):
        expected_error = b"missing profile settings" if mode == "default-configure" else b"authentication input required"
        if expected_error not in transcript or b"--interactive" not in transcript:
            raise RuntimeError("default mode did not explain missing input and interactive opt-in")
        if any(prompt in transcript for prompt in (b"Portal URL: ", b"Password: ", b"Authenticator code: ")):
            raise RuntimeError("default mode prompted despite available terminal")
    restored = termios.tcgetattr(slave)
    restored[3] &= ~getattr(termios, "PENDIN", 0)
    expected = list(original)
    expected[3] &= ~getattr(termios, "PENDIN", 0)
    if restored != expected:
        raise RuntimeError("terminal settings were not restored")
    for secret in (password, code):
        if secret and (secret in transcript or secret in output):
            raise RuntimeError("CLI exposed secret input")
    if (process.returncode == 0) != (mode in ("login", "paste", "configure")):
        raise RuntimeError("unexpected command status")
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    termios.tcsetattr(slave, termios.TCSANOW, original)
    os.close(master)
    os.close(slave)
