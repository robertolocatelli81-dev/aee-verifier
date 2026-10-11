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


class TestUniversalKindCheckReadsAeeMethod(unittest.TestCase):
    """L595-L608: every carried record that binds to this run (its
    aeeRunBinding equals the derived digest) and names a covering kind
    satisfies every constraint of that kind.  ``aeeMethod: intercepted`` is a
    constraint of the arming and sealed kinds and ``reconstructed`` of the
    examination kind (L1329, L1335, L1337): a missing or unregistered
    aeeMethod violates it, it does not take the record out of scope."""

    ROWS = [{"attackId": a, "containmentObserved": l, "basis": "substrate", "method": "intercepted",
             "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]}
            for a, l in (("CO-EXFIL-1", "no_egress"), ("CO-EXFIL-2", "no_egress"), ("FS-WRITE-1", "no_write"))]

    def codes_with(self, extra):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}] + extra
        st, _ = B.build(records=recs, rows=self.ROWS, observedAttacks=[])
        return report(st).code_set()

    def test_control_accepts(self):
        self.assertEqual(self.codes_with([]), [])
        self.assertEqual(self.codes_with([{"name": "md", "kind": "moat-drop", "drop": ["aeeMethod"]}]), [])

    def test_down_seal_with_registered_method_is_refused(self):
        self.assertIn("sealed-record-invalid", self.codes_with([{"name": "s2", "kind": "sealed", "stillArmed": False}]))

    def test_down_seal_without_method_is_refused(self):
        self.assertIn("sealed-record-invalid",
                      self.codes_with([{"name": "s2", "kind": "sealed", "stillArmed": False, "drop": ["aeeMethod"]}]))

    def test_down_seal_with_unregistered_method_is_refused(self):
        self.assertIn("sealed-record-invalid",
                      self.codes_with([{"name": "s2", "kind": "sealed", "stillArmed": False, "method": "bogus"}]))

    def test_seal_missing_method_only(self):
        self.assertIn("sealed-record-invalid", self.codes_with([{"name": "s2", "kind": "sealed", "drop": ["aeeMethod"]}]))

    def test_arming_bad_armed_at_without_method(self):
        self.assertIn("arming-record-invalid",
                      self.codes_with([{"name": "a2", "kind": "arming", "armedAt": "nope", "drop": ["aeeMethod"]}]))

    def test_examination_without_method(self):
        self.assertIn("examination-record-invalid",
                      self.codes_with([{"name": "e2", "kind": "examination", "drop": ["aeeMethod"]}]))

    def test_observed_set_checked_on_seal_without_method(self):
        # N33: aeeObservedSet is compared on every parseable sealed record
        got = self.codes_with([{"name": "s2", "kind": "sealed", "observedSet": "00" * 32, "drop": ["aeeMethod"]}])
        self.assertIn("observed-set-mismatch", got)


class TestInterceptionWithoutMethodReachedByUniversalCheck(unittest.TestCase):
    """L595-L608 over the interception kind, L2232-L2233: a bound interception
    cited only by an artifact caught row escapes the per-row checks; the
    universal check must still refuse one whose aeeMethod is missing or
    unregistered (L1341-L1342).  Found while reviewing patch 0003."""

    def build(self, spec):
        import copy
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0].update(spec)
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(basis="artifact", attribution="paired")
        st, _ = B.build(records=recs, rows=rows)
        return report(st).code_set()

    def test_control_accepts(self):
        self.assertEqual(self.build({}), [])

    def test_missing_method(self):
        self.assertIn("interception-record-invalid", self.build({"drop": ["aeeMethod"]}))

    def test_unregistered_method(self):
        self.assertIn("interception-record-invalid", self.build({"extra": {"aeeMethod": "bogus"}}))


class TestEd25519ScalarRange(unittest.TestCase):
    def test_s_equal_to_L_is_rejected_even_where_it_would_verify(self):
        # RFC 8032 5.1.7: S must be in range 0 <= S < L.  With the identity as
        # public key and R, [S]B = R + [k]A holds for S = 0 and for S = L, so
        # only the range check separates them (tests/MUTATION.md listed the
        # `s >= L` -> `s > L` mutation as unconstructible; it is not).
        from aee_verifier import ed25519
        ident = bytes([1]) + bytes(31)
        self.assertTrue(ed25519.verify(ident, b"m", ident + bytes(32)))      # S = 0: in range, verifies
        self.assertFalse(ed25519.verify(ident, b"m", ident + ed25519.L.to_bytes(32, "little")))


class TestStdoutEncoding(unittest.TestCase):
    def test_non_ascii_reason_under_ascii_stdout(self):
        # Reasons quote statement text (here a CJK attackId).  Under a
        # non-UTF-8 stdout encoding the first build raised UnicodeEncodeError
        # before the JSON line; the line itself is ASCII and must still come out.
        st, _ = B.build()
        st["predicate"]["attackResults"][0]["attackId"] = "\u653b\u6483-1"
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(B.dumps(st))
            path = fh.name
        try:
            for enc in ("ascii", "latin-1"):
                env = dict(os.environ, PYTHONIOENCODING=enc)
                proc = subprocess.run([sys.executable, os.path.join(ROOT, "aee-verify"), path],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                self.assertEqual(proc.returncode, 1, proc.stderr.decode())
                line = json.loads(proc.stdout.decode("ascii").strip().splitlines()[-1])
                self.assertIn("row-attack-id-unknown", line["codes"])
        finally:
            os.unlink(path)


class TestRowAttackIdNotHashable(unittest.TestCase):
    def test_array_attack_id_is_a_reject_not_a_crash(self):
        # kills the verifier L357 `all` -> `any` mutation that MUTATION.md listed
        # as verdict-equivalent: with `any`, set() over an array attackId raised.
        st, _ = B.build()
        st["predicate"]["attackResults"][1]["attackId"] = ["CO-EXFIL-2"]
        self.assertIn("row-attack-id-malformed", report(st).code_set())


class TestSealOfAnotherRun(unittest.TestCase):
    def test_only_seal_bound_to_another_run_does_not_satisfy_existence(self):
        # L586-L589: the required sealed record must bind to THIS run.  Rows
        # here are caught only, so no row points at the seal.
        rows = [{"attackId": a, "containmentObserved": l, "basis": "substrate", "method": "intercepted",
                 "attribution": "paired", "actualLayer": "policy.egress_sinkhole", "refs": ["int1"]}
                for a, l in (("CO-EXFIL-1", "egress_captured"), ("CO-EXFIL-2", "egress_captured"),
                             ("FS-WRITE-1", "file_written"))]
        recs = [{"name": "int1", "kind": "interception"}, {"name": "seal", "kind": "sealed"}]
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertEqual(report(st).code_set(), [])                      # control: same run
        recs[1] = {"name": "seal", "kind": "sealed", "binding": "cd" * 32}
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertIn("sealed-record-missing", report(st).code_set())


class TestIgnoredMembersAreReported20261010(unittest.TestCase):
    """2026-10-10: an unrecognized member is ignored, as the in-toto parsing rules require (N10), and now REPORTED in `notes`
    so the reader of the verdict sees what the verifier did not read. The verdict and the codes are unchanged."""

    def _rep(self, st):
        return Verifier(None).verify_bytes(B.dumps(st))

    def test_statement_subject_and_predicate_members_are_named(self):
        st, _ = B.scenario_pass()
        base = self._rep(st)
        self.assertEqual(base.to_json_line()["verdict"], "accept")
        self.assertEqual([n for n in base.notes if "ignored unrecognized" in n], [])
        st["x_unknown_2026"] = "x"; st["subject"][0]["y_unknown_2026"] = "x"; st["predicate"]["z_unknown_2026"] = "x"
        rep = self._rep(st)
        self.assertEqual(rep.to_json_line(), base.to_json_line())          # ignored: the verdict does not move
        notes = [n for n in rep.notes if "ignored unrecognized" in n]
        self.assertEqual(len(notes), 3)
        self.assertTrue(any("statement member" in n and "x_unknown_2026" in n for n in notes))
        self.assertTrue(any("subject[0] member" in n and "y_unknown_2026" in n for n in notes))
        self.assertTrue(any("predicate member" in n and "z_unknown_2026" in n for n in notes))

    def test_aee_members_keep_their_own_rule_and_are_not_reported_here(self):
        st, _ = B.scenario_pass()
        st["predicate"]["aeeUnknown2026"] = "x"            # predicate-level aee* members: ignored per L779-L781 (N10), not a note
        rep = self._rep(st)
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertEqual([n for n in rep.notes if "ignored unrecognized" in n], [])

if __name__ == "__main__":
    unittest.main()
