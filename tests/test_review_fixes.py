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


class TestAnchoredSyntax(unittest.TestCase):
    """Python's ``$`` also matches before a final newline and ``\\d`` matches
    every Unicode decimal digit; the lowercase-64-hex and timestamp rules
    are ASCII and exact."""

    def assertRejectCode(self, st, code):
        rep = report(st)
        self.assertIn(code, rep.code_set(), rep.codes)

    def test_hex64_with_trailing_newline(self):
        # L213-L218: digests "already lowercase 64-hex"; L819-L820, L1454-L1458, L1613.
        H = B.h
        cases = [
            (dict(subjectDigest=H("artifact") + "\n"), "subject-digest-malformed"),
            (dict(substrateDigest=H("substrate-image") + "\n"), "substrate-digest-malformed"),
            (dict(catchPolicyDigest=H("catch-policy") + "\n"), "catch-policy-digest-malformed"),
            (dict(postureDigest=H("posture-config") + "\n"), "network-posture-digest-malformed"),
            (dict(runEntropyDigest=H("run-entropy") + "\n"), "run-entropy-digest-malformed"),
            (dict(expectedPayloads={"CO-EXFIL-1": [B.COMMIT_1 + "\n"], "FS-WRITE-1": [B.COMMIT_FS]}),
             "expected-payloads-malformed"),
            (dict(records=[{"name": "int1", "kind": "interception", "commitment": [B.COMMIT_1 + "\n"]},
                           {"name": "arm", "kind": "arming"}, {"name": "exam", "kind": "examination"},
                           {"name": "seal", "kind": "sealed"}]), "interception-record-invalid"),
            (dict(armExtra={"aeeRunSeq": 2, "aeePrevRunBinding": "ab" * 32 + "\n", "aeeChainScope": ["subject"]}),
             "arming-record-invalid"),
        ]
        for kw, code in cases:
            with self.subTest(code=code):
                st, _ = B.build(**kw)
                self.assertRejectCode(st, code)
        # control: the same arming chain members without the newline are accepted
        st, _ = B.build(armExtra={"aeeRunSeq": 2, "aeePrevRunBinding": "ab" * 32, "aeeChainScope": ["subject"]})
        self.assertEqual(report(st).code_set(), [])

    def test_timestamp_trailing_newline_and_unicode_digits(self):
        # L1784-L1802: issuedAt / armedAt are RFC 3339 (ASCII DIGIT) in the pinned profile.
        bad = ["2026-06-23T16:08:07Z\n", "\u0662\u0660\u0662\u0666-06-23T16:08:07Z",
               "2026-06-23T16:08:07.\u0665Z", "2026-06-23T16:08:\uff10\uff17Z"]
        for v in bad:
            with self.subTest(issuedAt=v):
                st, _ = B.build(issuedAt=v)
                self.assertRejectCode(st, "issued-at-malformed")
        for v in ["2026-06-23T16:00:00Z\n", "2026-06-23T16:00:00.\u0665Z"]:
            with self.subTest(armedAt=v):
                st, _ = B.build(armedAt=v)
                self.assertRejectCode(st, "arming-record-invalid")

    def test_base64_trailing_newline_after_padding(self):
        # DSSE payload is base64; "<b64>=\n" is not. Before the fix only
        # b64decode(validate=True) caught it (the regex admitted the newline).
        from aee_verifier.verifier import decode_base64
        for s in ("G620=\n", "G620==\n", "3pd==\n", "NPk_=\n"):
            self.assertIsNone(decode_base64(s), s)
        self.assertEqual(decode_base64("G620"), b"\x1b\xad\xb4")


if __name__ == "__main__":
    unittest.main()
