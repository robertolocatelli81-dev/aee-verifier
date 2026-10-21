"""Requirement-by-requirement tests, written from the spec text.

Each test names the spec area it exercises.  Reject tests assert that a
specific code is among those reported; accept tests assert an empty code set
and the expected recomputed ``result``.  Run: ``python3 -m unittest
discover -s tests`` (or ``python3 tests/test_verifier.py``).
"""

from __future__ import annotations

import base64
import copy
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

KEYS = [(B.SUBSTRATE_KEYID, B.SUBSTRATE_PUB)]


def run(statement, keys=None):
    data = statement if isinstance(statement, bytes) else B.dumps(statement)
    return Verifier(keys).verify_bytes(data)


def codes(statement, keys=None):
    return run(statement, keys).code_set()


def pass_rows(basis="substrate", refs=("arm", "seal")):
    """Three clean intercepted rows (one per manifest attack)."""
    rows = []
    for a in ("CO-EXFIL-1", "CO-EXFIL-2", "FS-WRITE-1"):
        row = {"attackId": a, "containmentObserved": "no_egress" if a.startswith("CO") else "no_write", "basis": basis,
               "method": "intercepted", "attribution": "paired", "actualLayer": "none"}
        if refs is not None:
            row["refs"] = list(refs)
        rows.append(row)
    return rows


class Base(unittest.TestCase):
    def assertReject(self, statement, code, keys=None):
        rep = run(statement, keys)
        got = rep.code_set()
        self.assertIn(code, got, "expected %r among %r\n%s" % (code, got, "\n".join("  %s: %s" % c for c in rep.codes)))
        self.assertTrue(rep.rejected)
        line = rep.to_json_line()
        self.assertEqual(line["verdict"], "reject")
        self.assertIsNone(line["result"])
        self.assertEqual(line["tiers"], [])
        return rep

    def assertAccept(self, statement, result, keys=None, tiers=None):
        rep = run(statement, keys)
        self.assertEqual(rep.code_set(), [], "unexpected reject:\n%s" % "\n".join("  %s: %s" % c for c in rep.codes))
        self.assertEqual(rep.result, result)
        line = rep.to_json_line()
        self.assertEqual(line["verdict"], "accept")
        self.assertEqual(line["codes"], [])
        self.assertNotIn("primaryCode", line)
        if tiers is not None:
            self.assertEqual(rep.tiers, tiers)
        return rep


# ---------------------------------------------------------------- Prerequisites
class TestStrictBytes(Base):
    """Spec 'Prerequisites': strict I-JSON on the raw bytes, statement-wide."""

    def good(self):
        return B.dumps(B.scenario_pass()[0])

    def test_duplicate_member_top_level(self):
        data = self.good()[:-1] + b',"_type":"https://in-toto.io/Statement/v1"}'
        self.assertReject(data, "duplicate-member")

    def test_duplicate_member_deep(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"classes": {', b'"classes": {"CO": [], ', 1)
        self.assertReject(data, "duplicate-member")

    def test_invalid_utf8(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\xffample"')
        self.assertReject(data, "invalid-utf8")

    def test_cesu8_surrogate_bytes(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\xed\xa0\x80ample"')
        self.assertReject(data, "invalid-utf8")

    def test_overlong_utf8(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\xc0\xafample"')
        self.assertReject(data, "invalid-utf8")

    def test_u_escape_with_sign(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\u+041ample"')
        self.assertReject(data, "ill-formed-string")

    def test_u_escape_with_underscore(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\u0_41ample"')
        self.assertReject(data, "ill-formed-string")

    def test_unpaired_high_surrogate_escape(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\ud800ample"')
        self.assertReject(data, "ill-formed-string")

    def test_unpaired_low_surrogate_escape(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\udc00ample"')
        self.assertReject(data, "ill-formed-string")

    def test_paired_surrogate_escape_accepted(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\ud83d\\ude00ample"')
        self.assertAccept(data, "pass")

    def test_noncharacter_raw(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\xef\xb7\x90ample"')  # U+FDD0
        self.assertReject(data, "ill-formed-string")

    def test_noncharacter_escaped_in_member_name(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st)[:-1] + b',"x\\uffff":1}'
        self.assertReject(data, "ill-formed-string")

    def test_noncharacter_supplementary_plane(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\\udbff\\udfffample"')  # U+10FFFF
        self.assertReject(data, "ill-formed-string")

    def test_raw_control_character(self):
        st, _ = B.scenario_pass()
        data = B.dumps(st).replace(b'"example-tool"', b'"ex\x01ample"')
        self.assertReject(data, "ill-formed-string")

    def test_depth_bound(self):
        st, _ = B.scenario_pass()
        # statement object is depth 1, predicate 2, extension member depth 3+
        deep_ok = "[" * 126 + "]" * 126   # statement(1) + predicate(2) + 126 arrays = 128 open containers
        deep_bad = "[" * 127 + "]" * 127  # 129
        data_ok = B.dumps(st).replace(b'"predicate": {', b'"predicate": {"x-ext": ' + deep_ok.encode() + b', ', 1)
        data_bad = B.dumps(st).replace(b'"predicate": {', b'"predicate": {"x-ext": ' + deep_bad.encode() + b', ', 1)
        self.assertAccept(data_ok, "pass")
        self.assertReject(data_bad, "nesting-depth-exceeded")

    def test_integer_safe_range(self):
        st, _ = B.scenario_pass()
        self.assertAccept(B.dumps(st).replace(b'"predicate": {', b'"predicate": {"x-ext": 9007199254740991, ', 1), "pass")
        self.assertReject(B.dumps(st).replace(b'"predicate": {', b'"predicate": {"x-ext": 9007199254740992, ', 1), "integer-out-of-safe-range")
        self.assertReject(B.dumps(st).replace(b'"predicate": {', b'"predicate": {"x-ext": -9007199254740992, ', 1), "integer-out-of-safe-range")

    def test_not_an_object(self):
        self.assertReject(b"[1,2]", "statement-not-object")

    def test_trailing_garbage(self):
        self.assertReject(self.good() + b" x", "malformed-json")

    def test_bom_rejected(self):
        self.assertReject(b"\xef\xbb\xbf" + self.good(), "malformed-json")

    def test_empty_input(self):
        self.assertReject(b"", "malformed-json")


# ------------------------------------------------------------- Statement shell
class TestStatementShell(Base):
    def test_statement_type(self):
        st, _ = B.scenario_pass()
        st["_type"] = "https://in-toto.io/Statement/v0.1"
        self.assertReject(st, "statement-type-mismatch")

    def test_predicate_type_retired_version(self):
        st, _ = B.scenario_pass()
        st["predicateType"] = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6"
        self.assertReject(st, "predicate-type-mismatch")

    def test_predicate_type_missing(self):
        st, _ = B.scenario_pass()
        del st["predicateType"]
        self.assertReject(st, "predicate-type-mismatch")

    def test_subject_zero_or_two(self):
        st, _ = B.scenario_pass()
        st["subject"] = []
        self.assertReject(st, "subject-count")
        st["subject"] = [{"digest": {"sha256": B.h("artifact")}}, {"digest": {"sha256": B.h("artifact")}}]
        self.assertReject(st, "subject-count")

    def test_subject_digest_uppercase(self):
        st, _ = B.scenario_pass()
        st["subject"][0]["digest"]["sha256"] = st["subject"][0]["digest"]["sha256"].upper()
        self.assertReject(st, "subject-digest-malformed")

    def test_subject_digest_missing(self):
        st, _ = B.scenario_pass()
        st["subject"][0]["digest"] = {"sha512": "ab" * 64}
        self.assertReject(st, "subject-digest-malformed")

    def test_subject_extra_algorithm_ignored(self):
        st, _ = B.scenario_pass()
        st["subject"][0]["digest"]["sha512"] = "AB" * 64
        del st["subject"][0]["name"]
        self.assertAccept(st, "pass")

    def test_predicate_missing(self):
        st, _ = B.scenario_pass()
        del st["predicate"]
        self.assertReject(st, "predicate-missing")

    def test_retired_spellings(self):
        for old in ("does_not_assert", "interceptRecords", "interceptRefs"):
            st, _ = B.scenario_pass()
            st["predicate"][old] = []
            self.assertReject(st, "retired-spelling")

    def test_unknown_members_ignored(self):
        st, _ = B.scenario_pass()
        st["predicate"]["evidenceTier"] = "attested"
        st["predicate"]["aeeSomething"] = {"ordered": 3}
        st["predicate"]["vendorExtension"] = [1, 2]
        st["x-top"] = True
        self.assertAccept(st, "pass", KEYS, tiers=["attested"] * 3)

    def test_envelope_input_unwrapped(self):
        st, _ = B.scenario_pass()
        env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(B.dumps(st)).decode(),
               "signatures": [{"keyid": "producer", "sig": base64.b64encode(bytes(64)).decode()}]}
        rep = self.assertAccept(json.dumps(env).encode(), "pass")
        self.assertTrue(any("envelope" in n for n in rep.notes))

    def test_envelope_wrong_payload_type(self):
        st, _ = B.scenario_pass()
        env = {"payloadType": "application/json", "payload": base64.b64encode(B.dumps(st)).decode(), "signatures": [{"sig": "AA=="}]}
        self.assertReject(json.dumps(env).encode(), "envelope-payload-type")

    def test_envelope_payload_not_base64(self):
        env = {"payloadType": "application/vnd.in-toto+json", "payload": "***", "signatures": [{"sig": "AA=="}]}
        self.assertReject(json.dumps(env).encode(), "envelope-payload-not-base64")

    def test_envelope_payload_not_object(self):
        env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(b"[1]").decode(), "signatures": [{"sig": "AA=="}]}
        self.assertReject(json.dumps(env).encode(), "statement-not-object")

    def test_envelope_inner_strictness(self):
        st, _ = B.scenario_pass()
        inner = B.dumps(st)[:-1] + b',"_type":"https://in-toto.io/Statement/v1"}'
        env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(inner).decode(), "signatures": [{"sig": "AA=="}]}
        self.assertReject(json.dumps(env).encode(), "duplicate-member")


# ------------------------------------------------------------ predicate fields
class TestPredicateFields(Base):
    def test_result_out_of_vocabulary(self):
        st, _ = B.scenario_pass()
        st["predicate"]["result"] = "PASS"
        self.assertReject(st, "result-out-of-vocabulary")
        del st["predicate"]["result"]
        self.assertReject(st, "result-out-of-vocabulary")

    def test_result_mismatch(self):
        st, _ = B.scenario_fail()
        st["predicate"]["result"] = "pass"
        self.assertReject(st, "result-mismatch")
        st, _ = B.scenario_pass()
        st["predicate"]["result"] = "pass_indirect"
        self.assertReject(st, "result-mismatch")

    def test_issued_at_profile(self):
        for bad in ("2026-06-23t16:08:07Z", "2026-06-23T16:08:07z", "2026-06-23T16:08:07+05:00", "2026-06-23T16:08:07",
                    "2026-06-23 16:08:07Z", "2026-02-30T16:08:07Z", "2026-13-01T16:08:07Z", "2026-06-23T24:08:07Z",
                    "2026-06-23T16:08:07.Z", 1719160087, None):
            st, _ = B.scenario_pass()
            if bad is None:
                del st["predicate"]["issuedAt"]
            else:
                st["predicate"]["issuedAt"] = bad
            self.assertReject(st, "issued-at-malformed")

    def test_issued_at_accepted_forms(self):
        for good in ("2026-06-23T16:08:07Z", "2026-06-23T16:08:07+00:00", "2026-06-23T16:08:07-00:00",
                     "2026-06-23T16:08:07.123456789Z", "2024-02-29T00:00:00Z", "2026-06-30T23:59:60Z"):
            st, _ = B.build(issuedAt=good, armedAt="2024-02-28T00:00:00Z", observedAttacks=[],
                            records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}], rows=pass_rows())
            self.assertAccept(st, "pass")

    def test_does_not_assert(self):
        st, _ = B.scenario_pass()
        st["predicate"]["doesNotAssert"] = "not an array"
        self.assertReject(st, "does-not-assert-malformed")
        st["predicate"]["doesNotAssert"] = ["ok", 3]
        self.assertReject(st, "does-not-assert-malformed")
        del st["predicate"]["doesNotAssert"]
        self.assertAccept(st, "pass")
        st["predicate"]["doesNotAssert"] = []
        self.assertAccept(st, "pass")

    def test_required_objects(self):
        for member, code in (("observationEnvironment", "observation-environment-malformed"),
                             ("coverage", "coverage-malformed"), ("attackResults", "attack-results-malformed")):
            st, _ = B.scenario_pass()
            del st["predicate"][member]
            self.assertReject(st, code)
            st["predicate"][member] = "x"
            self.assertReject(st, code)

    def test_attack_results_rows_must_be_objects(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"].append("row")
        self.assertReject(st, "attack-results-malformed")


# ------------------------------------------------------- observationEnvironment
class TestEnvironment(Base):
    def test_descriptor_digests(self):
        for member, code in (("substrate", "substrate-digest-malformed"), ("catchPolicy", "catch-policy-digest-malformed")):
            st, _ = B.scenario_pass()
            env = st["predicate"]["observationEnvironment"]
            env[member]["digest"]["sha256"] = env[member]["digest"]["sha256"].upper()
            self.assertReject(st, code)
            del env[member]
            self.assertReject(st, code)

    def test_environment_members_required_without_substrate_rows(self):
        for member, code in (("networkPosture", "network-posture-malformed"), ("corpus", "corpus-malformed"),
                             ("observationVocabulary", "vocabulary-malformed"), ("substrate", "substrate-digest-malformed"),
                             ("catchPolicy", "catch-policy-digest-malformed")):
            st, _ = B.scenario_artifact_only()
            del st["predicate"]["observationEnvironment"][member]
            rep = self.assertReject(st, code)
            self.assertNotIn("run-binding-not-derivable", rep.code_set())

    def test_network_posture_vocabulary(self):
        for bad in ("SINKHOLE", "open", "", 3, None):
            st, _ = B.scenario_pass()
            np_ = st["predicate"]["observationEnvironment"]["networkPosture"]
            if bad is None:
                del np_["posture"]
            else:
                np_["posture"] = bad
            self.assertReject(st, "network-posture-out-of-vocabulary")

    def test_network_posture_all_registered_values(self):
        for p in ("allowlist", "no_network", "sinkhole", "unsafe_bypass_egress"):
            st, _ = B.build(posture=p, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                            rows=pass_rows(), observedAttacks=[])
            self.assertAccept(st, "pass")

    def test_network_posture_digest(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["networkPosture"]["digest"]["sha256"] = "zz" * 32
        self.assertReject(st, "network-posture-digest-malformed")

    def test_network_posture_edit_after_arming_breaks_binding(self):
        """Binding version 2 digests the carried networkPosture object."""
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["networkPosture"]["note"] = "added after signing"
        self.assertReject(st, "run-binding-mismatch")
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["networkPosture"]["posture"] = "allowlist"
        self.assertReject(st, "run-binding-mismatch")

    def test_manifest_classes_required(self):
        st, _ = B.scenario_pass()
        del st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["classes"]
        self.assertReject(st, "manifest-malformed")
        del st["predicate"]["observationEnvironment"]["corpus"]["manifest"]
        self.assertReject(st, "manifest-malformed")

    def test_manifest_attack_in_two_classes(self):
        st, _ = B.build(classes={"CO": ["CO-EXFIL-1", "CO-EXFIL-2"], "FS": ["FS-WRITE-1", "CO-EXFIL-1"]})
        self.assertReject(st, "manifest-attack-in-multiple-classes")

    def test_manifest_non_string_ids(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["classes"]["CO"] = ["CO-EXFIL-1", 2]
        self.assertReject(st, "manifest-malformed")

    def test_manifest_zero_attacks(self):
        st, _ = B.build(classes={}, expectedPayloads=None, assessedClasses=[], records=[], rows=[])
        self.assertReject(st, "manifest-no-attacks")
        st, _ = B.build(classes={"CO": []}, expectedPayloads=None, assessedClasses=["CO"], records=[], rows=[])
        self.assertReject(st, "manifest-no-attacks")

    def test_manifest_empty_class_beside_real_one_is_fine(self):
        st, _ = B.build(classes={"CO": ["CO-EXFIL-1", "CO-EXFIL-2"], "FS": ["FS-WRITE-1"], "ZZ": []},
                        assessedClasses=["CO", "FS", "ZZ"])
        self.assertAccept(st, "fail")

    def test_expected_payloads_rules(self):
        bad_maps = [
            {"NOT-AN-ATTACK": [B.COMMIT_1]},
            {"CO-EXFIL-1": []},
            {"CO-EXFIL-1": [B.COMMIT_1.upper()]},
            {"CO-EXFIL-1": sorted([B.COMMIT_1, "zz" * 32])},
            {"CO-EXFIL-1": sorted([B.COMMIT_1, B.COMMIT_2.upper()])},
            {"CO-EXFIL-1": [B.COMMIT_1, B.COMMIT_1]},
            {"CO-EXFIL-1": sorted([B.COMMIT_1, B.COMMIT_2])[::-1]},
            {"CO-EXFIL-1": "not-an-array"},
            "not-an-object",
        ]
        for bad in bad_maps:
            st, _ = B.build(expectedPayloads=bad)
            self.assertReject(st, "expected-payloads-malformed")

    def test_expected_payloads_optional(self):
        st, _ = B.build(expectedPayloads=None, rows=[dict(r, attribution="paired") for r in B.DEFAULT["rows"]])
        self.assertAccept(st, "fail")

    def test_corpus_digest_mismatch(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["corpus"]["digest"]["sha256"] = B.h("other")
        self.assertReject(st, "corpus-digest-mismatch")
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["classes"]["CO"].append("CO-EXFIL-3")
        self.assertReject(st, "corpus-digest-mismatch")

    def test_corpus_digest_malformed(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["corpus"]["digest"]["sha256"] = B.h("x").upper()
        self.assertReject(st, "corpus-digest-malformed")

    def test_vocabulary_rules(self):
        st, _ = B.scenario_pass()
        voc = st["predicate"]["observationEnvironment"]["observationVocabulary"]
        for mutate in (
            lambda v: v.__setitem__("labels", v["labels"][::-1]),
            lambda v: v.__setitem__("labels", v["labels"] + [v["labels"][0]]),
            lambda v: v.__setitem__("caught", ["not_a_label"]),
            lambda v: v.__setitem__("labels", v["labels"] + ["\U0001F600"]),
            lambda v: v.__setitem__("labels", v["labels"] + ["zz_mixed_\U0001F600_bmp"]),
            lambda v: v.__setitem__("labels", v["labels"][:2] + v["labels"][2:][::-1]),
            lambda v: v.__setitem__("labels", v["labels"] + [1]),
            lambda v: v.__setitem__("labels", "egress_captured"),
            lambda v: v.pop("caught"),
        ):
            s2 = copy.deepcopy(st)
            mutate(s2["predicate"]["observationEnvironment"]["observationVocabulary"])
            self.assertReject(s2, "vocabulary-malformed")
        self.assertTrue(voc)

    def test_vocabulary_caught_may_equal_labels(self):
        st, _ = B.build(labels=["egress_captured", "file_written"], caught=["egress_captured", "file_written"],
                        records=[{"name": "int1", "kind": "interception"}, {"name": "int2", "kind": "interception", "commitment": [B.COMMIT_2]},
                                 {"name": "int3", "kind": "interception", "commitment": [B.COMMIT_FS]}, {"name": "seal", "kind": "sealed"}],
                        rows=[{"attackId": "CO-EXFIL-1", "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
                               "attribution": "pinned", "actualLayer": "policy.egress_sinkhole", "refs": ["int1"]},
                              {"attackId": "CO-EXFIL-2", "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
                               "attribution": "paired", "actualLayer": "none", "refs": ["int2"]},
                              {"attackId": "FS-WRITE-1", "containmentObserved": "file_written", "basis": "substrate", "method": "intercepted",
                               "attribution": "pinned", "actualLayer": "policy.fs_deny", "refs": ["int3"]}],
                        observedAttacks=["CO-EXFIL-1", "CO-EXFIL-2", "FS-WRITE-1"])
        self.assertAccept(st, "fail", KEYS, tiers=["attested"] * 3)

    def test_vocabulary_digest_mismatch(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["observationVocabulary"]["digest"]["sha256"] = B.h("other")
        self.assertReject(st, "vocabulary-digest-mismatch")

    def test_vocabulary_narrowing_breaks_binding(self):
        """Narrowing caught after the run re-derives the vocabulary digest for free; the binding must catch it."""
        st, _ = B.scenario_fail()
        voc = st["predicate"]["observationEnvironment"]["observationVocabulary"]
        voc["caught"] = ["file_written"]
        voc["digest"]["sha256"] = B.sha256_hex(B.canonicalize({"caught": voc["caught"], "labels": voc["labels"]}))
        st["predicate"]["result"] = "pass_indirect"
        rep = self.assertReject(st, "run-binding-mismatch")
        self.assertNotIn("vocabulary-digest-mismatch", rep.code_set())

    def test_utf16_order_not_codepoint_order_in_vocabulary(self):
        """BMP-only is enforced, so a supplementary-plane label is malformed before any sort question arises."""
        st, _ = B.scenario_pass()
        voc = st["predicate"]["observationEnvironment"]["observationVocabulary"]
        voc["labels"] = sorted(voc["labels"] + ["\U00010000"])
        self.assertReject(st, "vocabulary-malformed")

    def test_run_entropy(self):
        st, _ = B.scenario_pass()
        del st["predicate"]["observationEnvironment"]["runEntropy"]
        rep = self.assertReject(st, "run-entropy-missing")
        self.assertIn("run-binding-not-derivable", rep.code_set())
        self.assertNotIn("run-binding-mismatch", rep.code_set())
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["runEntropy"]["digest"]["sha256"] = "x" * 64
        self.assertReject(st, "run-entropy-digest-malformed")
        st, _ = B.scenario_artifact_only()
        self.assertNotIn("runEntropy", st["predicate"]["observationEnvironment"])
        self.assertAccept(st, "fail")
        st["predicate"]["observationEnvironment"]["runEntropy"] = {"digest": {"sha256": B.h("e")}}
        self.assertAccept(st, "fail")
        st["predicate"]["observationEnvironment"]["runEntropy"] = {"digest": {"sha256": "nope"}}
        self.assertReject(st, "run-entropy-digest-malformed")


# -------------------------------------------------------------------- coverage
class TestCoverage(Base):
    def test_partition_class_in_two(self):
        st, _ = B.build(outOfScope={"FS": "reason"})  # FS also assessed
        self.assertReject(st, "coverage-partition-violation")

    def test_partition_class_in_none(self):
        st, _ = B.build(assessedClasses=["CO"])  # FS nowhere, but FS row present
        self.assertReject(st, "coverage-partition-violation")
        # FS nowhere and no FS row: the partition rule is the only thing that catches it
        st, _ = B.build(assessedClasses=["CO"], rows=B.DEFAULT["rows"][:2],
                        records=[r for r in B.DEFAULT["records"] if r["name"] != "exam"])
        rep = self.assertReject(st, "coverage-partition-violation")
        self.assertEqual(rep.code_set(), ["coverage-partition-violation"])

    def test_partition_duplicate_assessed(self):
        st, _ = B.build(assessedClasses=["CO", "FS", "CO"])
        self.assertReject(st, "coverage-partition-violation")

    def test_unknown_class(self):
        st, _ = B.build(assessedClasses=["CO", "FS", "XX"])
        self.assertReject(st, "coverage-unknown-class")
        st, _ = B.build(routedElsewhere={"XX": "elsewhere"})
        self.assertReject(st, "coverage-unknown-class")

    def test_coverage_types(self):
        st, _ = B.scenario_pass()
        st["predicate"]["coverage"]["outOfScope"] = {"FS": 3}
        self.assertReject(st, "coverage-malformed")
        st, _ = B.scenario_pass()
        st["predicate"]["coverage"]["assessedClasses"] = "CO"
        self.assertReject(st, "coverage-malformed")
        st, _ = B.scenario_pass()
        del st["predicate"]["coverage"]["routedElsewhere"]
        self.assertReject(st, "coverage-malformed")

    def test_integrity_missing_row(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"].pop()
        self.assertReject(st, "coverage-integrity-mismatch")

    def test_integrity_row_for_disclosed_class(self):
        st, _ = B.scenario_degraded()
        st["predicate"]["attackResults"].append({"attackId": "FS-WRITE-1", "containmentObserved": "no_write", "basis": "artifact",
                                                 "method": "intercepted", "attribution": "paired", "actualLayer": "none"})
        st["predicate"]["result"] = "degraded"
        self.assertReject(st, "coverage-integrity-mismatch")

    def test_degraded_scenarios(self):
        st, _ = B.scenario_degraded()
        self.assertAccept(st, "degraded")
        st, _ = B.scenario_fully_skipped()
        self.assertAccept(st, "degraded", tiers=[])


# ------------------------------------------------------------------------ rows
class TestRows(Base):
    def test_attack_id_unknown(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["attackId"] = "CO-EXFIL-9"
        self.assertReject(st, "row-attack-id-unknown")

    def test_attack_id_not_string(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["attackId"] = 7
        self.assertReject(st, "row-attack-id-malformed")

    def test_duplicate_attack_id(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][1]["attackId"] = "CO-EXFIL-1"
        self.assertReject(st, "duplicate-attack-id")

    def test_actual_layer_missing(self):
        st, _ = B.scenario_pass()
        del st["predicate"]["attackResults"][0]["actualLayer"]
        self.assertReject(st, "actual-layer-missing")
        st["predicate"]["attackResults"][0]["actualLayer"] = None
        self.assertReject(st, "actual-layer-missing")

    def test_actual_layer_none_on_clean_row(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["actualLayer"] = "policy.egress_sinkhole"
        self.assertReject(st, "actual-layer-not-none")

    def test_actual_layer_none_on_caught_row_is_fine(self):
        st, _ = B.scenario_fail()
        st["predicate"]["attackResults"][0]["actualLayer"] = "none"
        self.assertAccept(st, "fail")

    def test_observation_refs_types(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationRefs"] = [0.0, 1]
        self.assertReject(st, "observation-refs-malformed")
        st["predicate"]["attackResults"][0]["observationRefs"] = ["0", 1]
        self.assertReject(st, "observation-refs-malformed")
        st["predicate"]["attackResults"][0]["observationRefs"] = [True, 1]
        self.assertReject(st, "observation-refs-malformed")
        st["predicate"]["attackResults"][0]["observationRefs"] = 0
        self.assertReject(st, "observation-refs-malformed")

    def test_observation_ref_out_of_range_any_row(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationRefs"] = [0, 2]
        self.assertReject(st, "observation-ref-out-of-range")
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationRefs"] = [-1, 1]
        self.assertReject(st, "observation-ref-out-of-range")
        st, _ = B.scenario_pass_indirect()  # row 1 is artifact
        st["predicate"]["attackResults"][1]["observationRefs"] = [9]
        self.assertReject(st, "observation-ref-out-of-range")
        st, _ = B.scenario_artifact_only()
        st["predicate"]["attackResults"][1]["observationRefs"] = [0]
        self.assertReject(st, "observation-ref-out-of-range")

    def test_substrate_row_needs_refs(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationRefs"] = []
        self.assertReject(st, "substrate-row-no-refs")
        del st["predicate"]["attackResults"][0]["observationRefs"]
        self.assertReject(st, "substrate-row-no-refs")

    def test_substrate_row_fail_closed_is_invalid(self):
        for field, value in (("containmentObserved", "unknown_label"), ("containmentObserved", None), ("method", "guessed"), ("method", None)):
            st, _ = B.scenario_pass()
            if value is None:
                del st["predicate"]["attackResults"][0][field]
            else:
                st["predicate"]["attackResults"][0][field] = value
            st["predicate"]["result"] = "fail"
            self.assertReject(st, "substrate-row-fail-closed")

    def test_substrate_row_bad_attribution_only_forces_fail(self):
        """Coverage validity names containmentObserved, basis and method; attribution's fail-closed arm is the result alone."""
        for value in ("firm", None, 3):
            st, _ = B.scenario_pass()
            if value is None:
                del st["predicate"]["attackResults"][0]["attribution"]
            else:
                st["predicate"]["attackResults"][0]["attribution"] = value
            st["predicate"]["result"] = "fail"
            self.assertAccept(st, "fail", KEYS, tiers=["attested"] * 3)
            st["predicate"]["result"] = "pass"
            self.assertReject(st, "result-mismatch")

    def test_artifact_row_fail_closed_forces_fail(self):
        for field, value in (("containmentObserved", "unknown_label"), ("containmentObserved", None), ("basis", "inferred"),
                             ("basis", None), ("method", "artifact_reported"), ("attribution", "strong"), ("basis", 3)):
            st, _ = B.scenario_artifact_only()
            row = st["predicate"]["attackResults"][0]
            if value is None:
                del row[field]
            else:
                row[field] = value
            st["predicate"]["result"] = "fail"
            self.assertAccept(st, "fail")
            st["predicate"]["result"] = "pass_indirect"
            self.assertReject(st, "result-mismatch")

    def test_fail_closed_basis_tier_is_declared(self):
        st, _ = B.scenario_pass_indirect()
        st["predicate"]["attackResults"][1]["basis"] = "substrate_observed"
        st["predicate"]["result"] = "fail"
        self.assertAccept(st, "fail", KEYS, tiers=["attested", "declared", "attested"])

    def test_observation_selectors_ignored(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationSelectors"] = ["flow-1", "flow-2"]
        st["predicate"]["attackResults"][1]["observationSelectors"] = 42
        self.assertAccept(st, "pass")

    def test_producer_members_on_rows_ignored(self):
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["confidence"] = "high"
        self.assertAccept(st, "pass")


# --------------------------------------------------------------- result rules
class TestResultRecompute(Base):
    def test_pass(self):
        self.assertAccept(B.scenario_pass()[0], "pass")

    def test_fail_from_caught(self):
        self.assertAccept(B.scenario_fail()[0], "fail")

    def test_pass_indirect_artifact_and_reconstructed(self):
        self.assertAccept(B.scenario_pass_indirect()[0], "pass_indirect")
        st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}, {"name": "exam", "kind": "examination"}],
                        rows=[{"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "substrate", "method": "intercepted",
                               "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
                              {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "substrate", "method": "intercepted",
                               "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
                              {"attackId": "FS-WRITE-1", "containmentObserved": "no_write", "basis": "substrate", "method": "reconstructed",
                               "attribution": "paired", "actualLayer": "none", "refs": ["exam"]}], observedAttacks=[])
        self.assertAccept(st, "pass_indirect")

    def test_worst_wins(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        assessedClasses=["CO"], outOfScope={"FS": "n/a"},
                        rows=[{"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "artifact", "method": "intercepted",
                               "attribution": "paired", "actualLayer": "none"},
                              {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "substrate", "method": "intercepted",
                               "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]}], observedAttacks=[])
        self.assertAccept(st, "degraded")  # degraded < pass_indirect
        st, _ = B.build(assessedClasses=["CO"], outOfScope={"FS": "n/a"},
                        records=[{"name": "int1", "kind": "interception"}, {"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        rows=B.DEFAULT["rows"][:2])
        self.assertAccept(st, "fail")  # fail < degraded

    def test_result_never_reads_records_or_keys(self):
        st, _ = B.scenario_pass()
        self.assertAccept(st, "pass", None, tiers=["unattested"] * 3)
        self.assertAccept(st, "pass", KEYS, tiers=["attested"] * 3)


# ----------------------------------------------------------- observationRecords
class TestRecordsStructure(Base):
    def test_envelope_fields(self):
        st, _ = B.scenario_pass()
        rec = st["predicate"]["observationRecords"][0]
        for mutate in (lambda r: r.__setitem__("payload", "***"), lambda r: r.__setitem__("payload", 5),
                       lambda r: r.pop("payload"), lambda r: r.pop("payloadType"), lambda r: r.__setitem__("payloadType", 1),
                       lambda r: r.__setitem__("signatures", []), lambda r: r.pop("signatures"),
                       lambda r: r.__setitem__("signatures", [{"keyid": "k"}]),
                       lambda r: r.__setitem__("signatures", r["signatures"] + [{"keyid": "k"}]),
                       lambda r: r.__setitem__("signatures", r["signatures"] + [{"sig": 5}])):
            s2 = copy.deepcopy(st)
            mutate(s2["predicate"]["observationRecords"][0])
            self.assertReject(s2, "observation-records-malformed")
        self.assertTrue(rec)

    def test_records_must_be_objects(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationRecords"].append("x")
        self.assertReject(st, "observation-records-malformed")
        st["predicate"]["observationRecords"] = "x"
        self.assertReject(st, "observation-records-malformed")

    def test_urlsafe_base64_accepted(self):
        st, _ = B.scenario_pass()
        for rec in st["predicate"]["observationRecords"]:
            raw = base64.b64decode(rec["payload"])
            rec["payload"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            sig = base64.b64decode(rec["signatures"][0]["sig"])
            rec["signatures"][0]["sig"] = base64.urlsafe_b64encode(sig).decode()
        self.assertAccept(st, "pass", KEYS, tiers=["attested"] * 3)

    def test_duplicate_record(self):
        st, info = B.scenario_fail()
        recs = st["predicate"]["observationRecords"]
        dup = copy.deepcopy(recs[0])
        dup["signatures"][0]["keyid"] = "other-hint"  # same PAE, same leaf
        recs.append(dup)
        st["predicate"]["batchRoot"] = B.merkle_root(info["leaves"] + [info["leaves"][0]])
        self.assertReject(st, "duplicate-record")

    def test_batch_root(self):
        st, _ = B.scenario_pass()
        st["predicate"]["batchRoot"] = B.h("wrong")
        self.assertReject(st, "batch-root-mismatch")
        st["predicate"]["batchRoot"] = st["predicate"]["batchRoot"].upper()
        self.assertReject(st, "batch-root-mismatch")
        del st["predicate"]["batchRoot"]
        self.assertReject(st, "batch-root-missing")
        st, _ = B.scenario_artifact_only()
        st["predicate"]["batchRoot"] = B.h("x")
        self.assertReject(st, "batch-root-unexpected")
        st["predicate"]["observationRecords"] = []
        self.assertReject(st, "batch-root-unexpected")

    def test_batch_root_shapes(self):
        """RFC 6962 recursive split for 1..6 leaves (odd counts never padded)."""
        for n in range(1, 7):
            recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}]
            recs += [{"name": "md%d" % i, "kind": "moat-drop", "extra": {"seq": i}} for i in range(n - 2)]
            if n == 1:
                # a single moat-drop record beside artifact-only rows: root == leaf hash
                st, _ = B.build(records=[{"name": "md0", "kind": "moat-drop"}], rows=pass_rows(basis="artifact", refs=None))
                self.assertAccept(st, "pass_indirect")
                continue
            st, _ = B.build(records=recs, observedAttacks=[], rows=pass_rows())
            self.assertEqual(len(st["predicate"]["observationRecords"]), n)
            self.assertAccept(st, "pass")

    def test_recordless_statement_with_substrate_row(self):
        st, _ = B.scenario_pass()
        del st["predicate"]["observationRecords"]
        del st["predicate"]["batchRoot"]
        self.assertReject(st, "observation-ref-out-of-range")


class TestRecordPayloads(Base):
    """Per-record payload rules: canonical +json, reserved members, kind constraints."""

    def test_media_type_must_end_in_json(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "payloadType": "application/vnd.x+cbor"}, {"name": "seal", "kind": "sealed"}],
                        rows=pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_media_type_suffix_case_insensitive(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "payloadType": "application/vnd.x+JSON"}, {"name": "seal", "kind": "sealed"}],
                        rows=pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def _pass_rows(self):
        return pass_rows()

    def test_payload_not_canonical(self):
        st, info = B.scenario_pass()
        p = info["payloads"]["arm"]
        raw = json.dumps(p, sort_keys=True, separators=(",", ": ")).encode()  # a space after ':'
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "rawPayload": raw}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_payload_unsorted_members(self):
        st, info = B.scenario_pass()
        p = info["payloads"]["arm"]
        raw = json.dumps(p, separators=(",", ":"), ensure_ascii=False).encode()
        raw = raw if raw != B.canonicalize(p) else raw  # builder dict order is not sorted
        self.assertNotEqual(raw, B.canonicalize(p))
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "rawPayload": raw}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_payload_duplicate_member(self):
        st, info = B.scenario_pass()
        raw = B.canonicalize(info["payloads"]["arm"])[:-1] + b',"aeeKind":"arming"}'
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "rawPayload": raw}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_payload_not_object(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "rawPayload": b'["x"]'}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_payload_big_integer(self):
        # canonicalize refuses 2**53 (not an I-JSON integer), so the payload bytes are patched after it
        patch = (b'"counter":123456789', b'"counter":' + str(2 ** 53).encode())
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "extra": {"counter": 123456789}, "patchPayload": patch},
                                 {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_payload_non_bmp_member_name(self):
        for name in ("\U0001F600", "mixed\U0001F600name", "nested"):
            extra = {name: 1} if name != "nested" else {"vendor": {"deep\U00010000": 1}}
            st, _ = B.build(records=[{"name": "arm", "kind": "arming", "extra": extra}, {"name": "seal", "kind": "sealed"}],
                            rows=self._pass_rows(), observedAttacks=[])
            self.assertReject(st, "referenced-record-unparseable")

    def test_payload_non_bmp_string_value_is_fine(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "extra": {"note": "\U0001F600"}}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_reserved_members_required(self):
        for drop in ("aeeRunBinding", "aeeKind", "aeeMethod"):
            st, _ = B.build(records=[{"name": "arm", "kind": "arming", "drop": [drop]}, {"name": "seal", "kind": "sealed"}],
                            rows=self._pass_rows(), observedAttacks=[])
            self.assertReject(st, "referenced-record-unparseable")
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "extra": {"aeeMethod": "live"}}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "referenced-record-unparseable")

    def test_run_binding_mismatch(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "binding": B.h("other-run")}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "run-binding-mismatch")

    def test_splice_from_other_configuration(self):
        """A record signed under another subject digest cannot be spliced in."""
        other, oinfo = B.build(subjectDigest=B.h("other-artifact"), records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                               rows=self._pass_rows(), observedAttacks=[])
        st, info = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}], rows=self._pass_rows(), observedAttacks=[])
        st["predicate"]["observationRecords"][0] = other["predicate"]["observationRecords"][0]
        from aee_verifier.verifier import pae
        leaves = [B.hashlib.sha256(b"\x00" + pae(r["payloadType"], base64.b64decode(r["payload"]))).digest() for r in st["predicate"]["observationRecords"]]
        st["predicate"]["batchRoot"] = B.merkle_root(leaves)
        self.assertReject(st, "run-binding-mismatch")

    def test_binding_version(self):
        st, _ = B.build(armExtra={"aeeBindingVersion": "1"}, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "binding-version-unsupported")
        st, _ = B.build(armExtra={"aeeBindingVersion": 2}, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertReject(st, "binding-version-unsupported")
        st, _ = B.build(armExtra={"aeeBindingVersion": "2"}, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_interception_commitment_rules(self):
        for bad in ([], [B.COMMIT_1.upper()], [B.COMMIT_1, B.COMMIT_1], sorted([B.COMMIT_1, B.COMMIT_2])[::-1], "x", None,
                    sorted([B.COMMIT_1, "zz" * 32]), sorted([B.COMMIT_1, 7], key=str)):
            recs = copy.deepcopy(B.DEFAULT["records"])
            if bad is None:
                recs[0]["drop"] = ["aeePayloadCommitment"]
            else:
                recs[0]["commitment"] = bad
            st, _ = B.build(records=recs, rows=[dict(r, attribution="paired") for r in B.DEFAULT["rows"]])
            rep = self.assertReject(st, "interception-record-invalid")
            self.assertIn("class-match-failed", rep.code_set())

    def test_arming_rules(self):
        cases = [
            ({"drop": ["armedAt"]}, "arming-record-invalid"),
            ({"armedAt": "2026-06-23T16:08:08Z"}, "arming-record-invalid"),           # after issuedAt
            ({"armedAt": "2026-06-23T16:08:07.000001Z"}, "arming-record-invalid"),    # after by a microsecond
            ({"armedAt": "2026-06-23t16:00:00Z"}, "arming-record-invalid"),
            ({"armedAt": "2026-06-23T16:00:00+02:00"}, "arming-record-invalid"),
            ({"postureDigest": B.h("other-posture")}, "arming-record-invalid"),
            ({"assessed": ["CO-EXFIL-2", "CO-EXFIL-1", "FS-WRITE-1"]}, "arming-record-invalid"),
            ({"assessed": ["CO-EXFIL-1", "CO-EXFIL-2", "FS-WRITE-1", "ZZ-1"]}, "arming-record-invalid"),
            ({"assessed": ["CO-EXFIL-1", "CO-EXFIL-1", "CO-EXFIL-2", "FS-WRITE-1"]}, "arming-record-invalid"),
            ({"drop": ["aeeAssessedAttacks"]}, "arming-record-invalid"),
            ({"method": "reconstructed"}, "arming-record-invalid"),
            ({"drop": ["aeePostureDigest"]}, "arming-record-invalid"),
        ]
        for spec, code in cases:
            st, _ = B.build(records=[dict({"name": "arm", "kind": "arming"}, **spec), {"name": "seal", "kind": "sealed"}],
                            rows=self._pass_rows(), observedAttacks=[])
            self.assertReject(st, code)

    def test_armed_at_equal_to_issued_at_is_fine(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming", "armedAt": "2026-06-23T16:08:07+00:00"}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_arming_chain_members(self):
        good = [{"aeeRunSeq": 1, "aeeChainScope": ["subject"]},
                {"aeeRunSeq": 2, "aeePrevRunBinding": B.h("prev"), "aeeChainScope": ["corpus", "networkPosture", "subject"]},
                {"aeeRunSeq": 7, "aeePrevRunBinding": B.h("prev"), "aeeChainScope": []}]
        for extra in good:
            st, _ = B.build(armExtra=extra, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                            rows=self._pass_rows(), observedAttacks=[])
            self.assertAccept(st, "pass")
        bad = [{"aeeRunSeq": 0, "aeeChainScope": ["subject"]},
               {"aeeRunSeq": -1, "aeeChainScope": ["subject"]},
               {"aeeRunSeq": True, "aeeChainScope": ["subject"]},
               {"aeeRunSeq": "1", "aeeChainScope": ["subject"]},
               {"aeeRunSeq": 1},
               {"aeeRunSeq": 1, "aeePrevRunBinding": B.h("prev"), "aeeChainScope": ["subject"]},
               {"aeeRunSeq": 2, "aeeChainScope": ["subject"]},
               {"aeeRunSeq": 2, "aeePrevRunBinding": B.h("prev").upper(), "aeeChainScope": ["subject"]},
               {"aeeRunSeq": 1, "aeeChainScope": ["subject", "corpus"]},
               {"aeeRunSeq": 1, "aeeChainScope": ["subject", "subject"]},
               {"aeeRunSeq": 1, "aeeChainScope": ["substrateKey"]},
               {"aeeRunSeq": 1, "aeeChainScope": "subject"},
               {"aeePrevRunBinding": B.h("prev")},
               {"aeeChainScope": ["subject"]}]
        for extra in bad:
            st, _ = B.build(armExtra=extra, records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                            rows=self._pass_rows(), observedAttacks=[])
            self.assertReject(st, "arming-record-invalid")

    def test_sealed_rules(self):
        cases = [
            ({"stillArmed": False}, "sealed-record-invalid"),
            ({"stillArmed": "true"}, "sealed-record-invalid"),
            ({"drop": ["aeeStillArmed"]}, "sealed-record-invalid"),
            ({"dropCount": 1}, "sealed-record-invalid"),
            ({"dropCount": 2, "dropBound": 1}, "sealed-record-invalid"),
            ({"dropCount": 0, "dropBound": "5"}, "sealed-record-invalid"),
            ({"dropCount": 1.0}, "sealed-record-invalid"),
            ({"dropCount": False}, "sealed-record-invalid"),
            ({"drop": ["aeeDropCount"]}, "sealed-record-invalid"),
            ({"postureDigest": B.h("other")}, "sealed-record-invalid"),
            ({"observedSet": B.h("wrong-set")}, "observed-set-mismatch"),
            ({"drop": ["aeeObservedSet"]}, "sealed-record-invalid"),
            ({"observedAttacks": ["ZZ-9"]}, "sealed-record-invalid"),
            ({"observedAttacks": ["CO-EXFIL-2", "CO-EXFIL-1"]}, "sealed-record-invalid"),
            ({"drop": ["aeeObservedAttacks"]}, "sealed-record-invalid"),
            ({"method": "reconstructed"}, "sealed-record-invalid"),
        ]
        for spec, code in cases:
            st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, dict({"name": "seal", "kind": "sealed"}, **spec)],
                            rows=self._pass_rows(), observedAttacks=[])
            rep = self.assertReject(st, code)
            # the only seal is defective: the existence requirement is the primary condition
            self.assertIn("sealed-record-missing", rep.code_set())
            self.assertEqual(rep.to_json_line()["primaryCode"], "sealed-record-missing")

    def test_sealed_drop_within_bound(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed", "dropCount": 3, "dropBound": 3}],
                        rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_sealed_observed_attack_needs_caught_row(self):
        st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
                        rows=self._pass_rows(), observedAttacks=["CO-EXFIL-1"])
        self.assertReject(st, "observed-attack-without-caught-row")
        self.assertAccept(B.scenario_fail()[0], "fail")  # observedAttacks=["CO-EXFIL-1"] with a caught row

    def test_sealed_observed_attack_satisfied_by_artifact_caught_row(self):
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(basis="artifact", attribution="paired")
        rows[0].pop("refs")
        recs = [r for r in B.DEFAULT["records"] if r["name"] != "int1"]
        st, _ = B.build(records=recs, rows=rows, observedAttacks=["CO-EXFIL-1"])
        self.assertAccept(st, "fail")

    def test_examination_method(self):
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[2]["method"] = "intercepted"
        st, _ = B.build(records=recs)
        rep = self.assertReject(st, "examination-record-invalid")
        self.assertIn("class-match-failed", rep.code_set())

    def test_unrecognised_reserved_member(self):
        for kind, name, code in (("arming", "arm", "arming-record-invalid"), ("sealed", "seal", "sealed-record-invalid")):
            recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}]
            for r in recs:
                if r["name"] == name:
                    r["extra"] = {"aeeFutureMember": 1}
            st, _ = B.build(records=recs, rows=self._pass_rows(), observedAttacks=[])
            self.assertReject(st, code)
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0]["extra"] = {"aeeNamespace": "net"}
        st, _ = B.build(records=recs)
        self.assertReject(st, "interception-record-invalid")

    def test_producer_members_inert(self):
        recs = [{"name": "arm", "kind": "arming", "extra": {"confidence": "low", "rank": 0}},
                {"name": "seal", "kind": "sealed", "extra": {"aeeVersion": "1", "vendor": {"ordered": 9}}}]
        st, _ = B.build(records=recs, rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_unknown_kind_ignored_but_counted(self):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"},
                {"name": "hw", "kind": "hardware-quote", "extra": {"aeeQuote": "..."}}]
        st, _ = B.build(records=recs, rows=self._pass_rows(), observedAttacks=[])
        self.assertAccept(st, "pass")
        # tamper the unknown record: batchRoot must still catch it
        st["predicate"]["observationRecords"][2]["payload"] = base64.b64encode(b'{"aeeKind":"hardware-quote"}').decode()
        self.assertReject(st, "batch-root-mismatch")

    def test_non_covering_kinds_in_observed_set(self):
        """moat-drop / uncommitted-observation are in batchRoot but not in aeeObservedSet."""
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "md", "kind": "moat-drop"}, {"name": "uo", "kind": "uncommitted-observation"}]
        st, _ = B.build(records=recs)
        self.assertAccept(st, "fail")

    def test_observed_set_includes_unreferenced_examination(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "exam2", "kind": "examination", "extra": {"states": ["snap-1", "snap-2"]}}]
        st, _ = B.build(records=recs)
        self.assertAccept(st, "fail")
        # drop exam2 from the carried set but keep the seal: observed set no longer recomputes
        st["predicate"]["observationRecords"].pop()
        st["predicate"]["batchRoot"] = B.merkle_root(_leaves(st))
        rep = self.assertReject(st, "observed-set-mismatch")
        self.assertIn("sealed-record-missing", rep.code_set())

    def test_record_deletion_detected_by_seal(self):
        st, info = B.scenario_fail()
        # delete the interception, relabel its row clean, recompute root
        st["predicate"]["observationRecords"].pop(0)
        for row in st["predicate"]["attackResults"]:
            row["observationRefs"] = [i - 1 for i in row["observationRefs"] if i > 0]
        row0 = st["predicate"]["attackResults"][0]
        row0.update(containmentObserved="no_egress", actualLayer="none", attribution="paired", observationRefs=[0, 2])
        st["predicate"]["result"] = "pass_indirect"
        st["predicate"]["batchRoot"] = B.merkle_root(_leaves(st))
        self.assertReject(st, "observed-set-mismatch")


def _leaves(st):
    from aee_verifier.verifier import pae
    return [B.hashlib.sha256(b"\x00" + pae(r["payloadType"], base64.b64decode(r["payload"] + "=="))).digest()
            for r in st["predicate"]["observationRecords"]]


# --------------------------------------------------------- coverage validity
class TestCoverageValidity(Base):
    def test_sealed_record_required_even_when_unreferenced(self):
        recs = [{"name": "int1", "kind": "interception"}, {"name": "arm", "kind": "arming"}]
        rows = [{"attackId": "CO-EXFIL-1", "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
                 "attribution": "paired", "actualLayer": "none", "refs": ["int1"]}]
        st, _ = B.build(records=recs, rows=rows, classes={"CO": ["CO-EXFIL-1"]}, expectedPayloads=None, assessedClasses=["CO"], observedAttacks=[])
        rep = self.assertReject(st, "sealed-record-missing")
        self.assertEqual(rep.to_json_line()["primaryCode"], "sealed-record-missing")

    def test_defective_second_seal_beside_valid_one(self):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}, {"name": "seal2", "kind": "sealed", "stillArmed": False}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        rep = self.assertReject(st, "sealed-record-invalid")
        self.assertNotIn("sealed-record-missing", rep.code_set())

    def test_unreferenced_defective_arming(self):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}, {"name": "arm2", "kind": "arming", "postureDigest": B.h("x")}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertReject(st, "arming-record-invalid")

    def test_unbound_record_of_other_run_is_not_evaluated_unless_referenced(self):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"},
                {"name": "arm2", "kind": "arming", "postureDigest": B.h("x"), "binding": B.h("another-run")}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertAccept(st, "pass")

    def test_interception_unresolved(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "int2", "kind": "interception", "commitment": [B.COMMIT_2]}]
        st, _ = B.build(records=recs)
        self.assertReject(st, "interception-unresolved")

    def test_interception_referenced_only_by_clean_row(self):
        st, _ = B.scenario_fail()
        st["predicate"]["attackResults"][1]["observationRefs"].append(0)  # clean row points at interception
        rep = self.assertReject(st, "clean-row-references-interception")

    def test_clean_artifact_row_referencing_interception(self):
        st, _ = B.scenario_fail()
        st["predicate"]["attackResults"][1].update(basis="artifact", observationRefs=[0])
        st["predicate"]["result"] = "fail"
        self.assertReject(st, "clean-row-references-interception")

    def test_artifact_row_references_are_outside_coverage_validity(self):
        """Coverage validity is stated over basis: substrate rows; an artifact caught row may cite an unbound interception."""
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0]["binding"] = B.h("some-other-run")
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(basis="artifact", attribution="paired")
        st, _ = B.build(records=recs, rows=rows)
        self.assertAccept(st, "fail", KEYS, tiers=["declared", "attested", "attested"])

    def test_class_match_caught_intercepted(self):
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0]["refs"] = ["arm"]  # caught row pointing at arming only
        rows[0]["attribution"] = "paired"
        st, _ = B.build(rows=rows)
        rep = self.assertReject(st, "class-match-failed")
        self.assertIn("interception-unresolved", rep.code_set())
        self.assertNotIn("row-resolves-unrecognised-kind", rep.code_set())
        self.assertNotIn("row-resolves-non-covering-kind", rep.code_set())

    def test_class_match_reconstructed_needs_examination(self):
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[2]["refs"] = ["arm", "seal"]
        st, _ = B.build(rows=rows)
        self.assertReject(st, "class-match-failed")

    def test_class_match_clean_intercepted_needs_arming_and_seal(self):
        for refs in (["arm"], ["seal"]):
            rows = copy.deepcopy(B.DEFAULT["rows"])
            rows[1]["refs"] = refs
            st, _ = B.build(rows=rows)
            self.assertReject(st, "class-match-failed")

    def test_caught_reconstructed_row(self):
        recs = copy.deepcopy(B.DEFAULT["records"])
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(method="reconstructed", attribution="paired", refs=["exam"])
        recs[0]["name"] = "int1"
        st, _ = B.build(records=recs, rows=rows)
        self.assertReject(st, "interception-unresolved")  # int1 now unaccounted for
        rows[0]["refs"] = ["exam", "int1"]
        st, _ = B.build(records=recs, rows=rows)
        self.assertAccept(st, "fail")

    def test_row_resolving_only_non_covering_kind(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "md", "kind": "moat-drop"}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(refs=["md"], attribution="paired")
        st, _ = B.build(records=recs, rows=rows)
        rep = self.assertReject(st, "class-match-failed")
        self.assertIn("row-resolves-non-covering-kind", rep.code_set())

    def test_row_resolving_only_unknown_kind(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "hw", "kind": "hardware-quote"}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[1].update(refs=["hw"])
        st, _ = B.build(records=recs, rows=rows)
        rep = self.assertReject(st, "class-match-failed")
        self.assertIn("row-resolves-unrecognised-kind", rep.code_set())

    def test_non_covering_kind_beside_covering_is_fine(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "md", "kind": "moat-drop"}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0]["refs"] = ["int1", "md"]
        st, _ = B.build(records=recs, rows=rows)
        self.assertAccept(st, "fail")

    def test_referenced_non_covering_record_must_still_bind(self):
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "md", "kind": "moat-drop", "binding": B.h("other")}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0]["refs"] = ["int1", "md"]
        st, _ = B.build(records=recs, rows=rows)
        self.assertReject(st, "run-binding-mismatch")

    def test_method_cap(self):
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0]["method"] = "reconstructed"  # interception signed reconstructed
        st, _ = B.build(records=recs)
        self.assertReject(st, "method-cap-violation")
        # one live and one reconstructed interception: the weakest wins
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "int2", "kind": "interception", "method": "reconstructed", "commitment": [B.COMMIT_1]}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0]["refs"] = ["int1", "int2"]
        st, _ = B.build(records=recs, rows=rows)
        rep = self.assertReject(st, "method-cap-violation")
        self.assertEqual(rep.code_set(), ["method-cap-violation"])
        # a reconstructed caught row may cite a reconstructed interception beside its examination
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0]["method"] = "reconstructed"
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0].update(method="reconstructed", refs=["int1", "exam"])
        st, _ = B.build(records=recs, rows=rows)
        self.assertAccept(st, "fail")

    def test_pinned_attribution(self):
        # no expectedPayloads entry for the pinned attack
        st, _ = B.build(expectedPayloads={"FS-WRITE-1": [B.COMMIT_FS]})
        self.assertReject(st, "pinned-attribution-unsupported")
        # commitment does not match the corpus expectation
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[0]["commitment"] = [B.COMMIT_2]
        st, _ = B.build(records=recs)
        self.assertReject(st, "pinned-attribution-unsupported")
        # pinned clean row (no interception)
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[1]["attribution"] = "pinned"
        st, _ = B.build(rows=rows, expectedPayloads={"CO-EXFIL-1": [B.COMMIT_1], "CO-EXFIL-2": [B.COMMIT_2]})
        self.assertReject(st, "pinned-attribution-unsupported")
        # two interceptions, one without the expected value
        recs = copy.deepcopy(B.DEFAULT["records"]) + [{"name": "int2", "kind": "interception", "commitment": [B.COMMIT_2]}]
        rows = copy.deepcopy(B.DEFAULT["rows"])
        rows[0]["refs"] = ["int1", "int2"]
        st, _ = B.build(records=recs, rows=rows)
        self.assertReject(st, "pinned-attribution-unsupported")
        # ... and the honest shape with several values
        recs[-1]["commitment"] = sorted([B.COMMIT_1, B.COMMIT_2])
        st, _ = B.build(records=recs, rows=rows)
        self.assertAccept(st, "fail")

    def test_paired_is_always_allowed(self):
        st, _ = B.build(rows=[dict(r, attribution="paired") for r in B.DEFAULT["rows"]])
        self.assertAccept(st, "fail")

    def test_assessed_attacks_subset(self):
        recs = [{"name": "arm", "kind": "arming", "assessed": ["CO-EXFIL-1", "CO-EXFIL-2"]}, {"name": "seal", "kind": "sealed"}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertReject(st, "assessed-attacks-not-declared")
        # declared more than assessed (part-way loss disclosed): fine
        st, _ = B.build(records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}], rows=rows[:2],
                        assessedClasses=["CO"], outOfScope={"FS": "lost"}, observedAttacks=[])
        self.assertAccept(st, "degraded")

    def test_assessed_attacks_checked_on_every_bound_arming(self):
        recs = [{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"},
                {"name": "arm2", "kind": "arming", "assessed": ["CO-EXFIL-1"]}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        self.assertReject(st, "assessed-attacks-not-declared")

    def test_sealed_posture_must_match_each_resolved_arming(self):
        # arming with a different posture digest is itself invalid; the universal check catches it
        recs = [{"name": "arm", "kind": "arming", "postureDigest": B.h("x")}, {"name": "seal", "kind": "sealed"}]
        rows = pass_rows()
        st, _ = B.build(records=recs, rows=rows, observedAttacks=[])
        rep = self.assertReject(st, "arming-record-invalid")
        self.assertIn("class-match-failed", rep.code_set())


# ------------------------------------------------------------------ tiers
class TestEvidenceTier(Base):
    def test_no_policy_means_unattested(self):
        self.assertAccept(B.scenario_pass()[0], "pass", None, tiers=["unattested"] * 3)

    def test_policy_key_attests(self):
        self.assertAccept(B.scenario_fail()[0], "fail", KEYS, tiers=["attested"] * 3)

    def test_wrong_key_unattested(self):
        self.assertAccept(B.scenario_fail()[0], "fail", [("k", B.OTHER_PUB)], tiers=["unattested"] * 3)

    def test_keyid_is_only_a_hint(self):
        st, _ = B.scenario_pass()
        for r in st["predicate"]["observationRecords"]:
            r["signatures"][0]["keyid"] = "some-other-id"
        self.assertAccept(st, "pass", KEYS, tiers=["attested"] * 3)
        self.assertAccept(st, "pass", [("x", B.OTHER_PUB), (B.SUBSTRATE_KEYID, B.SUBSTRATE_PUB)], tiers=["attested"] * 3)

    def test_bad_signature_unattested_per_row(self):
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[2]["badSig"] = True  # examination record
        st, _ = B.build(records=recs)
        self.assertAccept(st, "fail", KEYS, tiers=["attested", "attested", "unattested"])

    def test_record_signed_by_other_key(self):
        recs = copy.deepcopy(B.DEFAULT["records"])
        recs[1]["seed"] = B.OTHER_SEED  # arming
        st, _ = B.build(records=recs)
        self.assertAccept(st, "fail", KEYS, tiers=["attested", "unattested", "attested"])
        self.assertAccept(st, "fail", KEYS + [("other", B.OTHER_PUB)], tiers=["attested"] * 3)

    def test_multiple_signatures_any_verifies(self):
        st, _ = B.scenario_pass()
        for r in st["predicate"]["observationRecords"]:
            r["signatures"].insert(0, {"keyid": "junk", "sig": base64.b64encode(bytes(64)).decode()})
        self.assertAccept(st, "pass", KEYS, tiers=["attested"] * 3)

    def test_tier_never_moves_result(self):
        st, _ = B.scenario_pass()
        self.assertAccept(st, "pass", [("k", B.OTHER_PUB)], tiers=["unattested"] * 3)


# -------------------------------------------------------------------- CLI
class TestCLI(unittest.TestCase):
    def run_cli(self, data: bytes, env_keys=None):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "statement.json")
            with open(path, "wb") as fh:
                fh.write(data)
            env = dict(os.environ)
            env.pop("AEE_SUBSTRATE_KEYS", None)
            if env_keys is not None:
                env["AEE_SUBSTRATE_KEYS"] = env_keys if os.path.isabs(env_keys) else B.key_policy_file(os.path.join(d, "keys.json"))
            proc = subprocess.run([sys.executable, "-m", "aee_verifier", path], cwd=ROOT, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            lines = proc.stdout.decode().splitlines()
            return proc.returncode, json.loads(lines[-1]), lines, proc.stderr.decode()

    def test_accept_exit_zero_and_last_line(self):
        rc, obj, lines, _ = self.run_cli(B.dumps(B.scenario_pass()[0]))
        self.assertEqual(rc, 0)
        self.assertEqual(obj, {"verdict": "accept", "codes": [], "result": "pass", "tiers": ["unattested"] * 3})
        self.assertEqual(len(lines), 2)

    def test_keys_via_environment(self):
        rc, obj, _, _ = self.run_cli(B.dumps(B.scenario_pass()[0]), env_keys="keys")
        self.assertEqual(rc, 0)
        self.assertEqual(obj["tiers"], ["attested"] * 3)

    def test_unreadable_key_file_is_fail_closed(self):
        rc, obj, _, err = self.run_cli(B.dumps(B.scenario_pass()[0]), env_keys="/nonexistent/keys.json")
        self.assertEqual(rc, 0)
        self.assertEqual(obj["tiers"], ["unattested"] * 3)
        self.assertIn("warning", err)

    def test_reject_exit_one(self):
        st, _ = B.scenario_pass()
        st["predicate"]["result"] = "fail"
        rc, obj, lines, _ = self.run_cli(B.dumps(st))
        self.assertEqual(rc, 1)
        self.assertEqual(obj["verdict"], "reject")
        self.assertEqual(obj["codes"], ["result-mismatch"])
        self.assertEqual(obj["primaryCode"], "result-mismatch")
        self.assertIsNone(obj["result"])
        self.assertTrue(lines[0].startswith("reject: result-mismatch:"))

    def test_garbage_input_rejects_with_code(self):
        rc, obj, _, _ = self.run_cli(b"\xff\xfe not json")
        self.assertEqual(rc, 1)
        self.assertEqual(obj["codes"], ["invalid-utf8"])

    def test_missing_file_exit_two(self):
        proc = subprocess.run([sys.executable, "-m", "aee_verifier", "/nonexistent/x.json"], cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout.decode().splitlines()[-1])["verdict"], "error")

    def test_launcher_script(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.json")
            with open(path, "wb") as fh:
                fh.write(B.dumps(B.scenario_degraded()[0]))
            proc = subprocess.run([os.path.join(ROOT, "aee-verify"), path], stdout=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout.decode().splitlines()[-1])["result"], "degraded")


if __name__ == "__main__":
    unittest.main(verbosity=1)
