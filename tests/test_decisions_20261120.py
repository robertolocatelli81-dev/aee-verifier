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
    with good_last the last record keeps its good signature after them; with no fakes every record is signed as built."""
    ids = ["A-%05d" % i for i in range(n)]
    recs = [{"name": "i%d" % i, "kind": "interception", "commitment": [B.h("c%d" % i)]} for i in range(n)]
    recs.append({"name": "seal", "kind": "sealed"})
    rows = [{"attackId": a, "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
             "attribution": "paired", "actualLayer": "policy.egress_sinkhole", "refs": ["i%d" % i]} for i, a in enumerate(ids)]
    st, _ = B.build(classes={"CO": ids}, expectedPayloads=None, assessedClasses=["CO"], records=recs, rows=rows,
                    observedAttacks=[])
    for i, rec in enumerate(st["predicate"]["observationRecords"][:n] if fakes else []):   # fakes=0: signed as built
        good = rec["signatures"]
        rec["signatures"] = [fake(j) for j in range(fakes)] + (good if good_last and i == n - 1 else [])
    return st


class CountVerify:
    """Counts ed25519.verify calls (and the failed ones) made through the verifier module, per signed message."""

    def __enter__(self):
        self.calls = self.failed = 0
        self.per_message = {}                     # PAE bytes -> [failed attempts, verified]
        self.orig = V.ed25519.verify

        def counted(*a):
            ok = self.orig(*a)
            self.calls += 1
            self.failed += not ok
            entry = self.per_message.setdefault(bytes(a[1]), [0, False])
            entry[0] += not ok
            entry[1] = entry[1] or ok
            return ok
        V.ed25519.verify = counted
        return self

    def failed_on_records_that_verify_nothing(self):
        return sum(f for f, ok in self.per_message.values() if not ok)

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

    def test_a_limit_of_more_than_4300_digits_is_read_as_its_value(self):
        # d0b8d7a: int() refused the string (CPython's 4300-digit limit) and the usage error did not name the variable
        data = B.dumps(B.scenario_pass()[0])
        zeros = "0" * 5000
        with TempFile(data) as path:
            # 3999 zeros put the first digit of the value in one 4000-digit block and the rest in the next
            for pad in (zeros, "0" * 3999):
                over = run_cli(path, {"AEE_MAX_INPUT_BYTES": pad + str(len(data) - 1)})
                self.assertEqual((over.returncode, last_line(over)), (2, UNREADABLE), (len(pad), over.stderr[-200:]))
                at = run_cli(path, {"AEE_MAX_INPUT_BYTES": pad + str(len(data))})
                self.assertEqual(at.returncode, 0, (len(pad), at.stderr[-200:]))
            for value in (zeros + str(len(data)), "9" * 5000, "1" + zeros):
                ok = run_cli(path, {"AEE_MAX_INPUT_BYTES": value})
                self.assertEqual(ok.returncode, 0, (value[:8], len(value), ok.stderr[-200:]))
            none = run_cli(path, {"AEE_MAX_INPUT_BYTES": zeros})                     # 5000 digits, value 0
            self.assertEqual((none.returncode, last_line(none)), (2, USAGE))
            self.assertIn(b"AEE_MAX_INPUT_BYTES", none.stderr)


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
        # each record verifies nothing at 16 x 3 = 48 failed attempts; the limit is checked before a record: 6 records
        self.assertEqual((c.calls, c.failed), (288, 288))                   # 64227ea: 6000 and 6000
        self.assertLess(elapsed, 8.0)                                      # 64227ea: 12.0 s; here about 1 s
        self.assertTrue(any(n.startswith("signature verification stopped once records that verify nothing had 256 or "
                                         "more failed attempts") for n in rep.notes))

    def test_a_good_record_left_untried_by_the_limit_is_not_attested_and_is_named(self):
        # records 0-2: one entry that verifies nothing, 3 keys = 9 failures; record 3: the same entry and the good one,
        # whose pinned keyid puts it first: the 10th attempt
        st = caught_rows(4, 1, good_last=True)
        for limit, last_tier in ((10, "attested"), (9, "unattested")):
            rep = Verifier(KEYS3, max_failed_verifications=limit).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line()["tiers"], ["unattested"] * 3 + [last_tier], limit)
            stopped = [n for n in rep.notes if "had %d or more failed attempts" % limit in n]
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
        # the third key is tried first after the first record; the last verification is the seal's, for N64
        self.assertEqual((c.calls, c.failed), (33, 2))

    def test_each_key_is_tried_once_per_entry(self):
        # records 0 and 2: one entry that verifies nothing, hinting the pinned keyid; record 1: signed by that key.
        # Each key once per entry: 3 failures for record 0 (no key verified yet) and 3 for record 2 (after the hinted
        # key verified record 1); trying a key twice costs one more failure each time
        st = caught_rows(3, 0)
        for i in (0, 2):
            st["predicate"]["observationRecords"][i]["signatures"] = [dict(fake(i), keyid=B.SUBSTRATE_KEYID)]
        with CountVerify() as c:
            rep = Verifier(KEYS3).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["unattested", "attested", "unattested"])
        self.assertEqual((c.calls, c.failed), (8, 6))                       # + 1 call for the seal (N64)

    def test_entries_hinting_a_pinned_keyid_are_tried_first(self):
        st, _ = B.scenario_pass()
        for rec in st["predicate"]["observationRecords"]:
            # an entry hinting an unpinned keyid that sorts before the pinned one, then one with no keyid: tried after
            rec["signatures"] = [dict(fake(1), keyid="a-unpinned"), {"sig": fake(2)["sig"]}] + rec["signatures"]
        with CountVerify() as c:
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * 3)
        self.assertEqual(c.failed, 0)

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
                lim, per_record = rnd.randrange(1, 12), rnd.randrange(1, 9)
                limited = Verifier(keys, max_signatures_per_record=per_record,
                                   max_failed_verifications=lim).verify_bytes(data)
            # the limit is checked before each record, which is then tried in full (N63)
            self.assertLessEqual(c.failed_on_records_that_verify_nothing(), lim - 1 + per_record * len(keys))
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

    def test_the_command_line_passes_the_failed_verification_limit(self):
        # record 0: one entry that verifies nothing (1 failure under the one pinned key); record 1: the same entry and
        # the good one, tried first.  With the limit at 1 record 1 is left untried
        st = caught_rows(2, 1, good_last=True)
        with TempFile(B.dumps(st)) as path, tempfile.TemporaryDirectory() as d:
            base = {"AEE_SUBSTRATE_KEYS": B.key_policy_file(os.path.join(d, "keys.json"))}
            self.assertIn('"tiers":["unattested","attested"]', last_line(run_cli(path, base)))
            for value in ("1", "0" * 5000 + "1"):                              # the second: more than 4300 digits
                one = run_cli(path, dict(base, AEE_MAX_FAILED_VERIFICATIONS=value))
                self.assertEqual(one.returncode, 0, one.stderr[-200:])
                self.assertIn('"tiers":["unattested","unattested"]', last_line(one))
                self.assertIn(b"had 1 or more failed attempts (limit, SPEC_NOTES N63): observationRecords 1 not tried",
                              one.stdout)

    def test_a_record_left_untried_is_named_once_and_asked_once(self):
        # row 0 cites the seal first, whose only entry verifies nothing (1 failure: the limit); rows 1 and 2 cite the
        # arming record first: left untried by row 1 and not asked again by row 2
        st, _ = B.scenario_pass()
        st["predicate"]["attackResults"][0]["observationRefs"] = [1, 0]
        st["predicate"]["observationRecords"][1]["signatures"] = [dict(fake(0), keyid=B.SUBSTRATE_KEYID)]
        with CountVerify() as c:
            rep = Verifier(KEYS, max_failed_verifications=1).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["unattested"] * 3)
        self.assertEqual((c.calls, c.failed), (1, 1))
        stopped = [n for n in rep.notes if "had 1 or more failed attempts" in n]
        self.assertEqual(len(stopped), 1, rep.notes)
        self.assertIn("observationRecords 0 not tried, so", stopped[0])

    def test_a_record_left_untried_stays_unverified_for_every_row_that_cites_it(self):
        # rows 0-2 cite records 0-2; row 3 cites records 0 and 2.  Record 0 verifies; record 1 verifies nothing (1
        # failure: the limit); record 2, good, is left untried by row 2 and asked again by row 3: it must not count as
        # verified the second time
        ids = ["A-%05d" % i for i in range(4)]
        recs = [{"name": "i%d" % i, "kind": "interception", "commitment": [B.h("c%d" % i)]} for i in range(3)]
        recs.append({"name": "seal", "kind": "sealed"})
        rows = [{"attackId": a, "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
                 "attribution": "paired", "actualLayer": "x", "refs": refs}
                for a, refs in zip(ids, (["i0"], ["i1"], ["i2"], ["i0", "i2"]))]
        st, _ = B.build(classes={"CO": ids}, expectedPayloads=None, assessedClasses=["CO"], records=recs, rows=rows,
                        observedAttacks=[])
        st["predicate"]["observationRecords"][1]["signatures"] = [fake(0)]
        data = B.dumps(st)
        free = Verifier(KEYS).verify_bytes(data)
        self.assertEqual(free.to_json_line()["tiers"], ["attested", "unattested", "attested", "attested"], free.codes)
        rep = Verifier(KEYS, max_failed_verifications=1).verify_bytes(data)
        self.assertEqual(rep.to_json_line()["tiers"], ["attested", "unattested", "unattested", "unattested"])

    def test_an_honest_statement_never_reaches_the_failed_verification_limit(self):
        # every record signed by a pinned key; K keys signing in turn; keyid of the policy, absent, or another name (the
        # form of the spec's examples).  On d0b8d7a every failed attempt counted: two keys in turn with no keyid lost
        # attestations from the 257th row at the default (N63); here the limit is 1, so one counted failure would show
        seeds = [bytes(range(10 + i, 42 + i)) for i in range(4)]
        n = 12
        ids = ["A-%05d" % i for i in range(n)]
        rows = [{"attackId": a, "containmentObserved": "egress_captured", "basis": "substrate", "method": "intercepted",
                 "attribution": "paired", "actualLayer": "x", "refs": ["i%d" % i]} for i, a in enumerate(ids)]
        for k_count in (1, 2, 3, 4):
            keys = [("pk-%d" % k, ed25519.public_key_from_seed(seeds[k])) for k in range(k_count)]
            for mode in ("policy", "absent", "other"):
                recs = [{"name": "i%d" % i, "kind": "interception", "commitment": [B.h("c%d" % i)],
                         "seed": seeds[(i * 7 + 3) % k_count],
                         "keyid": {"policy": "pk-%d" % ((i * 7 + 3) % k_count), "other": "<hex>", "absent": "x"}[mode]}
                        for i in range(n)] + [{"name": "seal", "kind": "sealed", "seed": seeds[k_count - 1]}]
                st, _ = B.build(classes={"CO": ids}, expectedPayloads=None, assessedClasses=["CO"], records=recs,
                                rows=rows, observedAttacks=[])
                if mode == "absent":
                    for rec in st["predicate"]["observationRecords"]:
                        del rec["signatures"][0]["keyid"]
                with CountVerify() as c:
                    rep = Verifier(keys, max_failed_verifications=1).verify_bytes(B.dumps(st))
                case = (k_count, mode, c.failed)
                self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * n, case)
                self.assertEqual(rep.refined_tiers, ["attested-sealed"] * n, case)
                self.assertFalse(any("limit, SPEC_NOTES N63" in x for x in rep.notes), (case, rep.notes))
                if k_count > 1 and mode != "policy":
                    self.assertGreater(c.failed, 0, case)           # failures happened, and were not counted

    def test_failures_of_a_record_that_verifies_are_not_counted_but_those_of_one_that_does_not_are(self):
        # record 0: 3 entries that verify nothing hinting the pinned keyid, then the good one: 9 failures, not counted
        # (it verifies); record 1: 4 entries that verify nothing: 12 failures, counted; record 2: good
        st = caught_rows(3, 0)
        r0, r1 = st["predicate"]["observationRecords"][0], st["predicate"]["observationRecords"][1]
        r0["signatures"] = [dict(fake(j), keyid=B.SUBSTRATE_KEYID) for j in range(3)] + [dict(r0["signatures"][0], keyid="none")]
        r1["signatures"] = [fake(9 + j) for j in range(4)]
        with CountVerify() as c:
            rep = Verifier(KEYS3, max_failed_verifications=10).verify_bytes(B.dumps(st))
        # limit 10: record 1 is tried in full (12 counted failures), record 2 is left untried
        self.assertEqual(rep.to_json_line()["tiers"], ["attested", "unattested", "unattested"])
        self.assertEqual(c.failed, 9 + 12)
        self.assertTrue(any(x.startswith("signature verification stopped once records that verify nothing had 10 or more")
                            and "observationRecords 2, 3 not tried" in x for x in rep.notes), rep.notes)   # 3: the seal (N64)
        with CountVerify() as c:
            rep = Verifier(KEYS3, max_failed_verifications=13).verify_bytes(B.dumps(st))      # 12 < 13: record 2 tried
        self.assertEqual(rep.to_json_line()["tiers"], ["attested", "unattested", "attested"])
        self.assertEqual(c.failed, 9 + 12)

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
            self.assertEqual([n for n in rep.notes if not n.startswith(self.NOTE)], base.notes)
            self.assertEqual(len(rep.notes), len(base.notes) + 1)

    def test_guard_a_name_that_only_looks_reserved_stays_unrecognized(self):
        for name in ("Aee", "AEEX", "_aee", " aee", "evidencetier", "EvidenceTier"):
            st, _ = B.scenario_pass()
            st["predicate"][name] = 1
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertFalse(any("the spec reserves" in n for n in rep.notes), name)
            self.assertTrue(any("ignored unrecognized predicate member" in n and name in n for n in rep.notes), name)


ZERO_SIG = base64.b64encode(bytes(64)).decode()
BAD_ENTRY = {"keyid": "k2", "sig": base64.b64encode(R_POINT + (5).to_bytes(32, "little")).decode()}


class TestAttestedSealedRefinement(unittest.TestCase):
    """D3 (N64): a caught or reconstructed row was `attested` while the sealed record the statement must carry (L586-L589)
    verified against no pinned key (64227ea: the default scenario with the seal's signature zeroed -> tiers attested,
    unattested, attested, nothing said).  The spec's tier is kept (L766-L775); the refinement is a new, named sub-tier
    (L775-L778), outside the JSON line.  Guard: the JSON line never moves (passes on 64227ea too)."""

    def _seal_zeroed(self):
        st, info = B.build()
        st["predicate"]["observationRecords"][info["index"]["seal"]]["signatures"][0]["sig"] = ZERO_SIG
        return st

    def test_an_attested_row_without_a_verifying_seal_is_not_attested_sealed_and_is_named(self):
        rep = Verifier(KEYS).verify_bytes(B.dumps(self._seal_zeroed()))
        self.assertEqual(rep.to_json_line()["tiers"], ["attested", "unattested", "attested"])     # the spec's tiers, kept
        self.assertEqual(rep.refined_tiers, ["attested", "unattested", "attested"])
        self.assertIn("refinement attested-sealed (consumer policy, spec L775-L778, SPEC_NOTES N64): not met by attested "
                      "row(s) 0, 2: no sealed record that satisfies its kind and binds to this run verifies against a "
                      "pinned key", rep.notes)
        ok = Verifier(KEYS).verify_bytes(B.dumps(B.build()[0]))
        self.assertEqual(ok.refined_tiers, ["attested-sealed"] * 3)
        self.assertIn("refinement attested-sealed (consumer policy, spec L775-L778, SPEC_NOTES N64): met by every "
                      "attested row", ok.notes)

    def test_the_refinement_follows_the_seal_signature_generative(self):
        rnd = random.Random(586)
        scenarios = [B.scenario_pass, B.scenario_fail, B.scenario_pass_indirect, B.scenario_degraded, B.scenario_artifact_only]
        seen = __import__("collections").Counter()
        for _ in range(50):
            st, info = rnd.choice(scenarios)()
            for rec in st["predicate"].get("observationRecords", []):
                if rnd.random() < 0.3:
                    rec["signatures"][0]["sig"] = ZERO_SIG
            keys = rnd.choice([None, KEYS, [("k2", B.OTHER_PUB)], KEYS + [("k2", B.OTHER_PUB)]])
            rep = Verifier(keys).verify_bytes(B.dumps(st))
            j = rep.to_json_line()
            self.assertEqual(sorted(j), sorted(k for k in ("verdict", "codes", "result", "tiers", "primaryCode") if k in j))
            seal_ok = False
            for rec in st["predicate"].get("observationRecords", []):
                payload = base64.b64decode(rec["payload"])
                if b'"aeeKind":"sealed"' in payload and keys:
                    pae = V.pae(rec["payloadType"], payload)
                    sig = base64.b64decode(rec["signatures"][0]["sig"])
                    seal_ok = seal_ok or any(ed25519.verify(pk, pae, sig) for _, pk in keys)
            self.assertEqual(len(rep.refined_tiers), len(j["tiers"]))
            for t, r in zip(j["tiers"], rep.refined_tiers):
                expected = "attested-sealed" if t == "attested" and seal_ok else t
                self.assertEqual(r, expected, (t, r, seal_ok))
                seen[(t, r)] += 1
        self.assertGreater(seen[("attested", "attested-sealed")], 0)
        self.assertGreater(seen[("attested", "attested")], 0)

    def test_one_verifying_seal_is_enough(self):
        recs = B.DEFAULT["records"] + [{"name": "seal2", "kind": "sealed", "extra": {"n": 2}}]
        for zeroed, refined in (("seal2", "attested-sealed"), ("seal", "attested-sealed")):   # either verifying seal is enough
            st, info = B.build(records=recs)
            st["predicate"]["observationRecords"][info["index"][zeroed]]["signatures"][0]["sig"] = ZERO_SIG
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line()["verdict"], "accept", rep.codes)
            self.assertEqual(rep.refined_tiers[0], refined, zeroed)

    def test_a_seal_the_limits_leave_untried_does_not_refine(self):
        st, info = B.build()
        rep = Verifier(KEYS + [("k2", B.OTHER_PUB)], max_failed_verifications=1).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * 3)
        self.assertEqual(rep.refined_tiers, ["attested-sealed"] * 3)                 # keyid hint: no failure at all
        st["predicate"]["observationRecords"][info["index"]["arm"]]["signatures"] = [BAD_ENTRY]
        rep = Verifier(KEYS + [("k2", B.OTHER_PUB)], max_failed_verifications=1).verify_bytes(B.dumps(st))
        # rows 0, 1, 2 cite int1; arm, seal; exam: the arming record verifies nothing (its failed attempts reach the
        # limit), so exam and the seal are left untried
        self.assertEqual(rep.to_json_line()["tiers"], ["attested", "unattested", "unattested"])
        self.assertEqual(rep.refined_tiers, ["attested", "unattested", "unattested"])

    def test_with_no_attested_row_the_seal_is_not_verified(self):
        # two caught rows whose records carry one entry that verifies nothing: no row is attested, so there is nothing
        # to refine and the seal (signed well) costs no verification: 2 entries x 3 keys
        with CountVerify() as c:
            rep = Verifier(KEYS3).verify_bytes(B.dumps(caught_rows(2, 1)))
        self.assertEqual(rep.refined_tiers, ["unattested"] * 2)
        self.assertEqual((c.calls, c.failed), (6, 6))
        self.assertFalse(any("refinement" in n for n in rep.notes), rep.notes)

    def test_guard_the_json_line_and_the_exit_status_do_not_move(self):
        with TempFile(B.dumps(self._seal_zeroed())) as path, tempfile.TemporaryDirectory() as d:
            proc = run_cli(path, {"AEE_SUBSTRATE_KEYS": B.key_policy_file(os.path.join(d, "k.json"))})
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(last_line(proc), '{"verdict":"accept","codes":[],"result":"fail","tiers":["attested","unattested","attested"]}')


class TestNonCoveringRecordSignatures(unittest.TestCase):
    """L1394-L1397 (N65): "A verifier MUST verify their signatures as it verifies any record's" for `moat-drop` and
    `uncommitted-observation`.  On 64227ea and 74dd0ba they were never verified: a good, a zeroed and an unpinned
    signature gave the same output, cited by a substrate row or not.  Guard: they cover nothing, so the JSON line does
    not move (passes on 64227ea too)."""

    def _build(self, kind, state, cited):
        recs = B.DEFAULT["records"] + [{"name": "nc", "kind": kind}]
        if state == "unpinned":
            recs[-1] = dict(recs[-1], seed=B.OTHER_SEED)
        rows = [dict(r) for r in B.DEFAULT["rows"]]
        if cited:
            rows[1]["refs"] = ["arm", "seal", "nc"]
        st, info = B.build(records=recs, rows=rows)
        if state == "zeroed":
            st["predicate"]["observationRecords"][info["index"]["nc"]]["signatures"][0]["sig"] = ZERO_SIG
        return B.dumps(st), info["index"]["nc"]

    def test_their_signatures_are_verified_and_a_failure_is_named(self):
        for kind in ("moat-drop", "uncommitted-observation"):
            for cited in (True, False):
                for state in ("good", "zeroed", "unpinned"):
                    data, idx = self._build(kind, state, cited)
                    rep = Verifier(KEYS).verify_bytes(data)
                    case = (kind, cited, state)
                    self.assertEqual(rep.non_covering_unverified, [] if state == "good" else [idx], case)
                    named = [n for n in rep.notes if n.startswith("observationRecords %d (moat-drop / " % idx)]
                    self.assertEqual(len(named), int(state != "good"), (case, rep.notes))
                    if named:
                        self.assertIn("SPEC_NOTES N65", named[0])

    def test_each_is_verified_once_and_only_with_keys(self):
        data, _ = self._build("moat-drop", "good", False)
        with CountVerify() as c:
            Verifier(KEYS).verify_bytes(data)
        self.assertEqual((c.calls, c.failed), (5, 0))            # int1, arm, seal, exam for the tiers; the moat-drop
        with CountVerify() as c:
            rep = Verifier(None).verify_bytes(data)
        self.assertEqual((c.calls, rep.non_covering_unverified), (0, []))

    def test_only_the_two_registered_kinds_are_verified_here(self):
        # a record of a kind this verifier does not know, cited by no row, its signature zeroed: L1396 speaks of the two
        # registered kinds only, so it is not verified (4 calls: int1, arm, seal, exam) and not listed
        recs = B.DEFAULT["records"] + [{"name": "u", "kind": "producer-kind", "badSig": True}]
        with CountVerify() as c:
            rep = Verifier(KEYS).verify_bytes(B.dumps(B.build(records=recs)[0]))
        self.assertEqual(rep.non_covering_unverified, [])
        self.assertEqual((rep.to_json_line()["tiers"], c.calls), (["attested"] * 3, 4))
        self.assertFalse(any("N65" in n for n in rep.notes), rep.notes)

    def test_verified_after_the_tiers_so_the_limits_never_take_a_tier(self):
        data, idx = self._build("uncommitted-observation", "zeroed", True)
        rep = Verifier(KEYS + [("k2", B.OTHER_PUB)], max_failed_verifications=1).verify_bytes(data)
        self.assertEqual(rep.to_json_line()["tiers"], ["attested"] * 3)
        self.assertEqual(rep.refined_tiers, ["attested-sealed"] * 3)
        self.assertEqual(rep.non_covering_unverified, [idx])

    def test_guard_the_json_line_does_not_move(self):
        for kind in ("moat-drop", "uncommitted-observation"):
            lines = set()
            for cited in (True, False):
                for state in ("good", "zeroed", "unpinned"):
                    lines.add(str(Verifier(KEYS).verify_bytes(self._build(kind, state, cited)[0]).to_json_line()))
            self.assertEqual(lines, {str({"verdict": "accept", "codes": [], "result": "fail",
                                          "tiers": ["attested", "attested", "attested"]})}, kind)


if __name__ == "__main__":
    unittest.main()
