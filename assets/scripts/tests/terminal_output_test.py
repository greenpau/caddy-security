"""Secret-output checks distinguish expected metadata from disclosed input."""

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "terminal_output", ROOT / "testdata/security_cli/terminal_output.py")
terminal_output = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal_output)


class TerminalOutputTests(unittest.TestCase):
    def test_totp_digits_in_expected_path_are_public_metadata(self):
        path = "/tmp/fixture-123456/token.json"
        for fields in [dict(status="success", token_path=path),
                       dict(token_path=path, status="success")]:
            terminal_output.assert_connect_output(json.dumps(fields).encode(), path)

    def test_unexpected_output_is_rejected_without_disclosing_it(self):
        path = "/tmp/fixture-123456/token.json"
        valid = json.dumps(dict(status="success", token_path=path))
        for output in [
            "123456\n" + valid, valid + "\n123456", valid + valid,
            json.dumps(dict(status="123456", token_path=path)),
            json.dumps(dict(status="success", token_path=path + "123456")),
            json.dumps(dict(status="success", token_path=path, code="123456")),
            '{"status":"123456",' + valid[1:],
            '{"token_path":"123456",' + valid[1:],
            "null", "[]", "{}", '"123456"',
            # An array of pairs must not masquerade as a JSON object.
            json.dumps([["status", "success"], ["token_path", path]]),
        ]:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, "^unexpected connect output$"):
                    terminal_output.assert_connect_output(output.encode(), path)


if __name__ == "__main__":
    unittest.main()
