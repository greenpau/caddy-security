"""Validate login output without confusing public path digits with a TOTP."""

import json


def assert_connect_output(output, token_path):
    # Retain pairs so duplicate fields cannot conceal an earlier secret value.
    try:
        fields = json.loads(output, object_pairs_hook=list)
    except (ValueError, UnicodeError):
        raise RuntimeError("unexpected connect output") from None
    expected = [("status", "success"), ("token_path", token_path)]
    if fields != expected and fields != expected[::-1]:
        raise RuntimeError("unexpected connect output")
