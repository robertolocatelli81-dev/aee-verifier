"""Regression tests for defects found in review (each fails on fea61aa).

Every case here is an input on which the first build either crashed (an
uncaught Python exception: exit status 1 with a traceback instead of the JSON
last line the harness reads) or accepted a statement the spec text calls
malformed.  The spec line each case rests on is named in the test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import builder as B  # noqa: E402
from aee_verifier.verifier import Verifier  # noqa: E402


def report(statement):
    data = statement if isinstance(statement, bytes) else B.dumps(statement)
    return Verifier(None).verify_bytes(data)


def cli(data: bytes):
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(data)
        path = fh.name
    try:
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "aee-verify"), path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finally:
        os.unlink(path)
    last = proc.stdout.decode().strip().splitlines()[-1] if proc.stdout.strip() else ""
    return proc.returncode, last, proc.stderr.decode()


class TestNoCrash(unittest.TestCase):
    """A malformed statement is a reject with a stated reason, never a crash."""

    def assertCliReject(self, data: bytes, code: str):
        rc, last, err = cli(data)
        self.assertNotIn("Traceback", err)
        self.assertEqual(rc, 1, err)
        line = json.loads(last)
        self.assertEqual(line["verdict"], "reject")
        self.assertIn(code, line["codes"])

    def test_integer_token_beyond_cpython_digit_limit(self):
        # L100-L102 safe-integer profile; CPython refuses int() on > 4300 digits.
        st, _ = B.build()
        st["predicate"]["producerCounter"] = 0
        data = B.dumps(st).replace(b'"producerCounter": 0', b'"producerCounter": ' + b"9" * 5000)
        self.assertIn(b"9" * 5000, data)
        self.assertCliReject(data, "integer-out-of-safe-range")
        self.assertCliReject(B.dumps(st).replace(b'"producerCounter": 0', b'"producerCounter": -' + b"1" * 5000),
                             "integer-out-of-safe-range")

    def test_integer_digit_count_boundary(self):
        # 2**53 - 1 (16 digits) is accepted; 2**53 (16 digits) and 10**16 (17 digits) are not.
        from aee_verifier.strict_json import StrictJSONError, loads_strict
        self.assertEqual(loads_strict(b"[9007199254740991,-9007199254740991]"), [2 ** 53 - 1, -(2 ** 53 - 1)])
        for tok in (b"9007199254740992", b"-9007199254740992", b"10000000000000000", b"-10000000000000000"):
            with self.assertRaises(StrictJSONError) as cm:
                loads_strict(b"[" + tok + b"]")
            self.assertEqual(cm.exception.kind, "integer")

    def test_huge_integer_inside_unreferenced_record_payload(self):
        # L148: payloads parse under the same profile; an unparseable payload covers nothing.
        recs = list(B.DEFAULT["records"]) + [{"name": "odd", "kind": "moat-drop",
                                               "rawPayload": b'{"aeeKind":"moat-drop","n":' + b"7" * 5000 + b"}"}]
        st, _ = B.build(records=recs)
        rep = report(st)  # must not raise
        self.assertEqual(rep.code_set(), [])
        rc, last, err = cli(B.dumps(st))
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(last)["verdict"], "accept")

    def test_manifest_class_not_an_array(self):
        # L788-L791: classes maps a class to an array of attack identifiers.
        st, _ = B.build()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["classes"]["FS"] = 9007199254740991
        self.assertCliReject(B.dumps(st), "manifest-malformed")

    def test_manifest_class_with_non_string_identifier(self):
        # a number beside a string the rows do not cover: the old coverage diff sorted int with str
        st, _ = B.build()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["classes"]["CO"] = ["CO-EXFIL-1", "CO-EXFIL-2", -1, "CO-EXTRA"]
        self.assertCliReject(B.dumps(st), "manifest-malformed")

    def test_expected_payloads_entry_with_nested_array(self):
        # L815-L821: entries are lowercase 64-hex strings; a nested array is malformed.
        st, _ = B.build()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["expectedPayloads"]["CO-EXFIL-1"] = [[B.COMMIT_1]]
        self.assertCliReject(B.dumps(st), "expected-payloads-malformed")


if __name__ == "__main__":
    unittest.main()
