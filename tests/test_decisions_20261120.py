"""Tests for the consumer policies decided on 2026-11-20 after the re-measure of the review findings (SPEC_NOTES N62
and after).  Each class names the decision and what was measured on 64227ea; every test fails on 64227ea except the
guards a class docstring names.
"""

from __future__ import annotations

import base64
import os
import random
import resource
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import builder as B  # noqa: E402
from aee_verifier import ed25519  # noqa: E402
from aee_verifier import verifier as V  # noqa: E402
from aee_verifier.verifier import Verifier  # noqa: E402

KEYS = [(B.SUBSTRATE_KEYID, B.SUBSTRATE_PUB)]
UNREADABLE = '{"verdict":"error","codes":["unreadable-input"],"result":null,"tiers":[]}'
USAGE = '{"verdict":"error","codes":["usage"],"result":null,"tiers":[]}'
THIRD_PUB = ed25519.public_key_from_seed(bytes(range(2, 34)))
KEYS3 = KEYS + [("k2", B.OTHER_PUB), ("k3", THIRD_PUB)]
NO_LIMIT = 1 << 30                                              # above every count in these tests
R_POINT = ed25519._encode_point(ed25519._mul(7, ed25519._B))   # a valid R: each entry costs a whole verification


def fake(i):
    """A signature entry that verifies nothing and costs a whole verification."""
    return {"keyid": "x%d" % i, "sig": base64.b64encode(R_POINT + (i + 1).to_bytes(32, "little")).decode()}


def caught_rows(n, fakes, good_last=False):
    """n caught substrate rows, row i citing its own interception record i carrying `fakes` entries that verify nothing;
    with good_last the last record keeps its good signature after them."""
    ids = ["A-%05d" % i for i in range(n)]
    recs = [{"name": "i%d" % i, "kind": "interception", "commitment": [B.h("c%d" % i)]} for i in range(n)]
    recs.append({"name": "seal", "kind": "sealed"})
    rows = [{"attackId": a, "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
             "attribution": "paired", "actualLayer": "policy.egress_sinkhole", "refs": ["i%d" % i]} for i, a in enumerate(ids)]
    st, _ = B.build(classes={"CO": ids}, expectedPayloads=None, assessedClasses=["CO"], records=recs, rows=rows,
                    observedAttacks=[])
    for i, rec in enumerate(st["predicate"]["observationRecords"][:n]):
        good = rec["signatures"]
        rec["signatures"] = [fake(j) for j in range(fakes)] + (good if good_last and i == n - 1 else [])
    return st


class CountVerify:
    """Counts ed25519.verify calls (and the failed ones) made through the verifier module."""

    def __enter__(self):
        self.calls = self.failed = 0
        self.orig = V.ed25519.verify

        def counted(*a):
            ok = self.orig(*a)
            self.calls += 1
            self.failed += not ok
            return ok
        V.ed25519.verify = counted
        return self

    def __exit__(self, *exc):
        V.ed25519.verify = self.orig


def run_cli(path, env_extra=None, preexec=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEE_") and k != "PYTHONPATH"}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, os.path.join(ROOT, "aee-verify"), path], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, preexec_fn=preexec, timeout=300)


def last_line(proc):
    return proc.stdout.decode().splitlines()[-1]


class TempFile:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(self.data)
            self.path = fh.name
        return self.path

    def __exit__(self, *exc):
        os.unlink(self.path)


class TestInputSizeLimit(unittest.TestCase):
    """D4 (N62): the input was read whole whatever its size (64227ea: /dev/zero read until the memory ran out; under a
    600 MB address-space limit 586 MB resident, then exit 2)."""

    def test_limit_plus_one_byte_is_unreadable_input_and_the_limit_itself_is_read(self):
        data = B.dumps(B.scenario_pass()[0])
        with TempFile(data) as path:
            at = run_cli(path, {"AEE_MAX_INPUT_BYTES": str(len(data))})
            self.assertEqual(at.returncode, 0, at.stderr[-300:])
            self.assertEqual(last_line(at), '{"verdict":"accept","codes":[],"result":"pass","tiers":["unattested","unattested","unattested"]}')
            over = run_cli(path, {"AEE_MAX_INPUT_BYTES": str(len(data) - 1)})
            self.assertEqual(over.returncode, 2, over.stderr[-300:])
            self.assertEqual(last_line(over), UNREADABLE)
            self.assertIn(b"larger than the limit of %d bytes" % (len(data) - 1), over.stderr)

    def test_endless_device_stops_at_the_default_limit_in_bounded_memory(self):
        # 64227ea: under this 300 MB address-space limit /dev/zero ended in MemoryError, after taking all of it
        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (300 << 20, 300 << 20))
        proc = run_cli("/dev/zero", preexec=limit)
        self.assertEqual(proc.returncode, 2, proc.stderr[-300:])
        self.assertEqual(last_line(proc), UNREADABLE)
        self.assertIn(b"larger than the limit of 16777216 bytes", proc.stderr)
        self.assertNotIn(b"MemoryError", proc.stderr)

    def test_a_limit_that_is_not_a_positive_decimal_integer_is_a_usage_error(self):
        data = B.dumps(B.scenario_pass()[0])
        bad = ["", "0", "00", "-1", "+5", " 5", "5 ", "1e3", "0x10", "5.0", "١٢", "１", "²",
               "1_000", "nan", "inf", "16MiB"]
        with TempFile(data) as path:
            for value in bad:
                proc = run_cli(path, {"AEE_MAX_INPUT_BYTES": value})
                self.assertEqual(proc.returncode, 2, (value, proc.stderr[-200:]))
                self.assertEqual(last_line(proc), USAGE, value)
                self.assertIn(b"AEE_MAX_INPUT_BYTES", proc.stderr)
            ok = run_cli(path, {"AEE_MAX_INPUT_BYTES": "0" + str(len(data))})      # leading zero: still decimal digits
            self.assertEqual(ok.returncode, 0, ok.stderr[-200:])

    def test_the_library_refuses_a_longer_input_and_a_limit_out_of_its_closed_list(self):
        data = B.dumps(B.scenario_pass()[0])
        self.assertEqual(Verifier(KEYS, max_input_bytes=len(data)).verify_bytes(data).to_json_line()["verdict"], "accept")
        with self.assertRaises(V.InputTooLarge):
            Verifier(KEYS, max_input_bytes=len(data) - 1).verify_bytes(data)
        with self.assertRaises(V.InputTooLarge):
            Verifier(KEYS).verify_bytes(b" " * (V.MAX_INPUT_BYTES + 1))
        for bad in (0, -1, True, False, 1.5, "5", None, b"5", [5]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Verifier(KEYS, max_input_bytes=bad)


class TestSignatureLimits(unittest.TestCase):
    """D1 (N63): every signature entry was tried against every pinned key (64227ea, three keys: 2000 entries that verify
    nothing on one record, 6000 verifications, 12.4 s for 240.6 kB; the same spread as 16 entries on 125 records, 12.0 s
    for 317.5 kB).  Guard: an unhashable keyid is no crash (passes on 64227ea too)."""

    def test_a_record_over_the_entry_limit_is_not_tried_and_its_rows_are_not_attested(self):
        for fakes, tier in ((15, "attested"), (16, "unattested")):          # 16 or 17 entries, the good one last
            st, _ = B.scenario_pass()
            rec = st["predicate"]["observationRecords"][1]                    # the seal every row cites
            rec["signatures"] = [fake(j) for j in range(fakes)] + rec["signatures"]
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line()["tiers"], [tier] * 3, fakes)
            capped = [n for n in rep.notes if "more than 16 signature entries with a 64-byte sig" in n]
            self.assertEqual(len(capped), int(tier == "unattested"), rep.notes)
            if capped:
                self.assertTrue(capped[0].startswith("observationRecords 1: "), capped)

    def test_entries_that_cannot_verify_do_not_count_toward_the_entry_limit(self):
        st, _ = B.scenario_pass()
        rec = st["predicate"]["observationRecords"][1]
        rec["signatures"] = [{"keyid": "x", "sig": s} for s in ("@@", "", "AAAA", base64.b64encode(bytes(63)).decode(),
                                                                  base64.b64encode(bytes(65)).decode())] * 10 + rec["signatures"]
        rep = Verifier(KEYS, max_signatures_per_record=1).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * 3)
        self.assertFalse(any("signature entries with a 64-byte sig" in n for n in rep.notes), rep.notes)

    def test_failed_verifications_of_a_statement_stop_at_the_limit(self):
        st = caught_rows(125, 16)
        with CountVerify() as c:
            t = time.perf_counter()
            rep = Verifier(KEYS3).verify_bytes(B.dumps(st))
            elapsed = time.perf_counter() - t
        self.assertEqual(rep.to_json_line()["tiers"], ["unattested"] * 125)
        self.assertEqual((c.calls, c.failed), (256, 256))                   # 64227ea: 6000 and 6000
        self.assertLess(elapsed, 8.0)                                      # 64227ea: 12.0 s; here about 0.9 s
        self.assertTrue(any(n.startswith("signature verification stopped after 256 failed attempts") for n in rep.notes))

    def test_a_good_record_left_untried_by_the_limit_is_not_attested_and_is_named(self):
        # records 0-2: one entry that verifies nothing, 3 keys = 9 failures; record 3: the same entry and the good one,
        # whose pinned keyid puts it first: the 10th attempt
        st = caught_rows(4, 1, good_last=True)
        for limit, last_tier in ((10, "attested"), (9, "unattested")):
            rep = Verifier(KEYS3, max_failed_verifications=limit).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line()["tiers"], ["unattested"] * 3 + [last_tier], limit)
            stopped = [n for n in rep.notes if "stopped after %d failed attempts" % limit in n]
            self.assertEqual(len(stopped), int(last_tier == "unattested"), rep.notes)

    def test_key_order_costs_one_failure_per_key_for_an_honest_statement_without_keyids(self):
        st, _ = B.build(classes={"CO": ["A-%05d" % i for i in range(30)]}, expectedPayloads=None, assessedClasses=["CO"],
                        records=[{"name": "i%d" % i, "kind": "interception", "commitment": [B.h("c%d" % i)]} for i in range(30)]
                        + [{"name": "seal", "kind": "sealed"}],
                        rows=[{"attackId": "A-%05d" % i, "containmentObserved": "egress_captured", "basis": "substrate",
                               "method": "intercepted", "attribution": "paired", "actualLayer": "x", "refs": ["i%d" % i]}
                              for i in range(30)], observedAttacks=[], signerSeed=bytes(range(2, 34)), keyid="unpinned")
        for rec in st["predicate"]["observationRecords"]:
            del rec["signatures"][0]["keyid"]
        with CountVerify() as c:
            rep = Verifier(KEYS3, max_failed_verifications=3).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * 30)    # signed by the third key, no keyid
        self.assertEqual((c.calls, c.failed), (32, 2))                      # the third key is tried first after the first record

    def test_limits_never_add_an_attestation_generative(self):
        rnd = random.Random(20261120)
        policies = [KEYS, KEYS3, [("k2", B.OTHER_PUB)], [("substrate-2026", THIRD_PUB), ("other", B.SUBSTRATE_PUB)]]
        scenarios = [B.scenario_pass, B.scenario_fail, B.scenario_pass_indirect, B.scenario_degraded]
        compared = attested_seen = taken = 0
        for _ in range(60):
            st, _ = rnd.choice(scenarios)()
            for rec in st["predicate"]["observationRecords"]:
                entries = [fake(rnd.randrange(10 ** 6)) for _ in range(rnd.randrange(0, 6))]
                good = rec["signatures"] if rnd.random() < 0.8 else []
                if rnd.random() < 0.3:
                    entries.append({"keyid": rnd.choice([1, None, ["l"], {"o": 1}, "substrate-2026"]), "sig": "@@"})
                pos = rnd.randrange(len(entries) + 1)
                rec["signatures"] = (entries[:pos] + good + entries[pos:]) or [fake(0)]
            data = B.dumps(st)
            keys = rnd.choice(policies)
            free = Verifier(keys, max_signatures_per_record=NO_LIMIT, max_failed_verifications=NO_LIMIT).verify_bytes(data)
            with CountVerify() as c:
                lim = rnd.randrange(1, 12)
                limited = Verifier(keys, max_signatures_per_record=rnd.randrange(1, 9),
                                   max_failed_verifications=lim).verify_bytes(data)
            self.assertLessEqual(c.failed, lim)
            a, b = free.to_json_line(), limited.to_json_line()
            self.assertEqual((a["verdict"], a["codes"], a["result"]), (b["verdict"], b["codes"], b["result"]))
            for x, y in zip(a["tiers"], b["tiers"]):
                compared += 1
                attested_seen += x == "attested"
                taken += (x, y) == ("attested", "unattested")
                self.assertTrue(y == x or (x, y) == ("attested", "unattested"), (x, y))
        self.assertGreater(attested_seen, 20)          # the generator reaches attested rows ...
        self.assertGreater(taken, 0)                   # ... and limits that take some away

    def test_the_command_line_reads_the_limits_and_refuses_values_out_of_the_closed_list(self):
        st, _ = B.scenario_pass()
        rec = st["predicate"]["observationRecords"][1]
        rec["signatures"] = [fake(0)] + rec["signatures"]
        with TempFile(B.dumps(st)) as path, tempfile.TemporaryDirectory() as d:
            policy = B.key_policy_file(os.path.join(d, "keys.json"))
            base = {"AEE_SUBSTRATE_KEYS": policy}
            self.assertIn('"tiers":["attested","attested","attested"]', last_line(run_cli(path, base)))
            one = run_cli(path, dict(base, AEE_MAX_SIGNATURES_PER_RECORD="1"))
            self.assertIn('"tiers":["unattested","unattested","unattested"]', last_line(one))
            self.assertEqual(one.returncode, 0)
            for name in ("AEE_MAX_SIGNATURES_PER_RECORD", "AEE_MAX_FAILED_VERIFICATIONS"):
                for value in ("", "0", "-3", "1.0", " 2", "\u0662"):
                    proc = run_cli(path, dict(base, **{name: value}))
                    self.assertEqual((proc.returncode, last_line(proc)), (2, USAGE), (name, value))
                    self.assertIn(name.encode(), proc.stderr)

    def test_limits_out_of_their_closed_list_are_refused_by_the_library(self):
        for name in ("max_signatures_per_record", "max_failed_verifications"):
            for bad in (0, -1, True, 2.0, "3", None):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    Verifier(KEYS, **{name: bad})

    def test_guard_unhashable_keyid_is_no_crash(self):
        st, _ = B.scenario_pass()
        for rec in st["predicate"]["observationRecords"]:
            rec["signatures"][0]["keyid"] = {"o": [1]}
        self.assertEqual(Verifier(KEYS3).verify_bytes(B.dumps(st)).to_json_line()["tiers"], ["attested"] * 3)


class TestReservedPredicateMembersAreNamed(unittest.TestCase):
    """D2 (N59): a carried `evidenceTier` or predicate-level `aee*` member was ignored as L779-L781 require, and was
    the only kind of ignored member not named (64227ea: `predicate.aeeInventato` -> accept, no note).  Guard: a name
    that only looks reserved stays an unrecognized member (passes on 64227ea too)."""

    NOTE = "ignored predicate member(s) the spec reserves, per L779-L781 (MUST be ignored, MUST NOT alter the derivation): "

    def test_reserved_members_are_named_in_one_note(self):
        for members, named in (({"aeeInventato": 1}, "aeeInventato"), ({"evidenceTier": "attested"}, "evidenceTier"),
                               ({"aeeX": 1, "evidenceTier": "declared", "aee": [2]}, "aee, aeeX, evidenceTier")):
            st, _ = B.scenario_pass()
            st["predicate"].update(members)
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertEqual([n for n in rep.notes if "the spec reserves" in n], [self.NOTE + named], members)

    def test_reserved_members_never_move_the_output_and_are_named_generative(self):
        rnd = random.Random(779)
        values = [None, True, 0, -1, 1.5, "", "attested", "unattested", [], ["attested"] * 3, {"tiers": ["attested"]},
                  {"aeeKind": "sealed"}]
        names = ["evidenceTier", "aee", "aeeTier", "aeeResult", "aeeKind", "aeeRunBinding", "aee\u00e9", "aee" + "z" * 300]
        for _ in range(40):
            scenario = rnd.choice([B.scenario_pass, B.scenario_fail, B.scenario_degraded, B.scenario_artifact_only])
            keys = rnd.choice([None, KEYS])
            base = Verifier(keys).verify_bytes(B.dumps(scenario()[0]))
            st, _ = scenario()
            chosen = rnd.sample(names, rnd.randrange(1, 4))
            for n in chosen:
                st["predicate"][n] = rnd.choice(values)
            rep = Verifier(keys).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line(), base.to_json_line(), chosen)
            self.assertEqual(rep.notes[:len(base.notes)], base.notes)
            self.assertEqual(len(rep.notes), len(base.notes) + 1)
            self.assertTrue(rep.notes[-1].startswith(self.NOTE), rep.notes[-1])

    def test_guard_a_name_that_only_looks_reserved_stays_unrecognized(self):
        for name in ("Aee", "AEEX", "_aee", " aee", "evidencetier", "EvidenceTier"):
            st, _ = B.scenario_pass()
            st["predicate"][name] = 1
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertFalse(any("the spec reserves" in n for n in rep.notes), name)
            self.assertTrue(any("ignored unrecognized predicate member" in n and name in n for n in rep.notes), name)


if __name__ == "__main__":
    unittest.main()
