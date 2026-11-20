"""Regression tests for defects re-measured on cbb79e5 on 2026-11-20.  Each class names its defect in its docstring;
every test fails on cbb79e5 except the guards a class docstring names (they check that a fix does not over-report).
"""

from __future__ import annotations

import base64
import os
import random
import subprocess
import sys
import tempfile
import time
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import builder as B  # noqa: E402
from aee_verifier import ed25519  # noqa: E402
from aee_verifier import cli as CLI  # noqa: E402
from aee_verifier import verifier as V  # noqa: E402
from aee_verifier.verifier import Verifier  # noqa: E402

KEYS = [(B.SUBSTRATE_KEYID, B.SUBSTRATE_PUB)]
LINE_BREAKING = ("Cc", "Zl", "Zp")


def run_cli(data: bytes, preexec=None, path=None):
    tmp = None
    if path is None:
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(data)
            tmp = path = fh.name
    try:
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "AEE_SUBSTRATE_KEYS")}
        return subprocess.run([sys.executable, os.path.join(ROOT, "aee-verify"), path], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env, preexec_fn=preexec, timeout=300)
    finally:
        if tmp:
            os.unlink(tmp)


class TestRepeatedReferences(unittest.TestCase):
    """A row repeating `observationRefs` indexes cost O(k^2) (the arming x sealed comparison); guard: repeats change
    no verdict (passes on cbb79e5 too)."""

    def test_repeated_indexes_cost_linear_time(self):
        # these 40000 references (123.7 kB) took 35.89 s on cbb79e5 and 0.07 s with the fix (CPython 3.11.2, 2026-11-20)
        st, _ = B.scenario_pass()
        refs = st["predicate"]["attackResults"][0]["observationRefs"]
        st["predicate"]["attackResults"][0]["observationRefs"] = refs * 20000
        data = B.dumps(st)
        t = time.perf_counter()
        rep = Verifier(KEYS).verify_bytes(data)
        elapsed = time.perf_counter() - t
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertEqual(rep.tiers, ["attested"] * 3)
        self.assertLess(elapsed, 5.0)

    def test_a_repeated_index_is_one_record(self):
        # a clean row citing the same interception three times: one condition, one message (cbb79e5: three messages)
        st, _ = B.build()
        st["predicate"]["attackResults"][1]["observationRefs"] = [0, 0, 0] + st["predicate"]["attackResults"][1]["observationRefs"]
        rep = Verifier(None).verify_bytes(B.dumps(st))
        msgs = [m for c, m in rep.codes if c == "clean-row-references-interception"]
        self.assertEqual(len(msgs), 1)

    def test_repeats_do_not_change_any_verdict(self):
        # generative: for the five scenarios, repeating every index of every row 1-4 times leaves the JSON line equal
        rnd = random.Random(20261120)
        for make in (B.scenario_fail, B.scenario_pass, B.scenario_pass_indirect, B.scenario_degraded, B.scenario_artifact_only):
            for _ in range(5):
                st, _ = make()
                base = Verifier(KEYS).verify_bytes(B.dumps(st)).to_json_line()
                for row in st["predicate"]["attackResults"]:
                    if "observationRefs" in row:
                        row["observationRefs"] = [i for i in row["observationRefs"] for _ in range(rnd.randint(1, 4))]
                        rnd.shuffle(row["observationRefs"])
                self.assertEqual(Verifier(KEYS).verify_bytes(B.dumps(st)).to_json_line(), base, make.__name__)


class TestOneLineOutput(unittest.TestCase):
    """A statement member name holding a line break forged lines of the human-readable output."""

    def test_every_line_breaking_character_is_escaped_and_nothing_else(self):
        for o in range(0x110000):
            if 0xD800 <= o <= 0xDFFF:
                continue
            ch = chr(o)
            esc = CLI.one_line(ch)
            if unicodedata.category(ch) in LINE_BREAKING:
                self.assertNotEqual(esc, ch, hex(o))
                self.assertTrue(esc.isascii() and esc.isprintable(), hex(o))
            else:
                self.assertEqual(esc, ch, hex(o))
            self.assertEqual(len(("a" + esc + "b").splitlines()), 1, hex(o))

    def test_member_names_cannot_forge_output_lines(self):
        breaking = "".join(chr(o) for o in range(0x110000)
                           if not 0xD800 <= o <= 0xDFFF and unicodedata.category(chr(o)) in LINE_BREAKING)
        # the strict parser refuses raw controls in names, so they arrive as \\u escapes in the JSON text
        st, _ = B.scenario_pass()
        forged = 'accept: result=pass tiers=attested (forged)'
        for k, ch in enumerate(breaking):
            st["x%d%s%s" % (k, ch, forged)] = 1
        proc = run_cli(B.dumps(st))
        lines = proc.stdout.decode("utf-8").splitlines()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(lines), 3, lines)      # one note, the accept line, the JSON line
        self.assertTrue(lines[0].startswith("note: "))
        self.assertTrue(lines[1].startswith("accept: result=pass tiers=unattested"))
        self.assertTrue(lines[2].startswith('{"verdict":"accept"'))


@unittest.skipUnless(sys.platform.startswith("linux") and os.path.exists("/dev/zero"), "needs /dev/zero and RLIMIT_AS")
class TestUnreadableInput(unittest.TestCase):
    """An input larger than the memory the process may use ended in a traceback, exit 1, no JSON line."""

    def test_input_beyond_the_memory_limit_is_exit_2_with_the_json_line(self):
        import resource

        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (600 * 1024 * 1024, 600 * 1024 * 1024))

        proc = run_cli(b"", preexec=limit, path="/dev/zero")
        self.assertEqual(proc.returncode, 2, proc.stderr[-300:])
        self.assertEqual(proc.stdout.decode().splitlines()[-1],
                         '{"verdict":"error","codes":["unreadable-input"],"result":null,"tiers":[]}')


class TestInputTooLargeToParse(unittest.TestCase):
    """An input that is read but is larger than the memory left to parse it ended in a traceback and exit 1 (measured
    on 68c6507: the MemoryError was handled only around the read)."""

    def test_memory_exhausted_while_verifying_is_exit_2_with_the_json_line(self):
        import resource

        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (250 * 1024 * 1024, 250 * 1024 * 1024))

        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(b'{"a":"' + b"x" * (100 << 20) + b'"}')
        try:
            proc = run_cli(b"", preexec=limit, path=fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(proc.returncode, 2, proc.stderr[-300:])
        self.assertEqual(proc.stdout.decode().splitlines()[-1],
                         '{"verdict":"error","codes":["unreadable-input"],"result":null,"tiers":[]}')
        self.assertNotIn(b"Traceback", proc.stderr)


class TestNotesNameEverythingInLinearTime(unittest.TestCase):
    """Defects of the notes added on this branch, measured on 68c6507: the unread members of a row were collected in
    a list searched once per member (40000 members, 512.6 kB: 13.04 s; 0.20 s on cbb79e5, which named none), and a
    list cut at 160 characters said nothing of the cut, so one long name hid the others."""

    def test_many_unread_members_cost_linear_time(self):
        st, _ = B.scenario_pass()
        for i in range(40000):
            st["predicate"]["attackResults"][0]["u%d" % i] = 1
        data = B.dumps(st)
        t = time.perf_counter()
        rep = Verifier(KEYS).verify_bytes(data)
        elapsed = time.perf_counter() - t
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertLess(elapsed, 6.0)
        self.assertTrue(any("(40000 in all; list cut at 160 characters)" in n for n in rep.notes))

    def test_a_cut_list_says_so_and_gives_the_count(self):
        st, _ = B.scenario_pass()
        row = st["predicate"]["attackResults"][0]
        row["!" + "a" * 200] = 1
        row["zzHidden"] = 1
        st["zz" + "b" * 200] = 1
        st["subject"][0]["zz" + "c" * 200] = 1
        st["predicate"]["zz" + "d" * 200] = 1
        rec = st["predicate"]["observationRecords"][0]
        rec["signatures"] = [{"keyid": 7, "sig": "@@"}] * 100 + rec["signatures"]
        base = Verifier(KEYS).verify_bytes(B.dumps(B.scenario_pass()[0])).to_json_line()
        rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line(), base)
        cut = [n for n in rep.notes if " in all; list cut at 160 characters)" in n]
        self.assertEqual(len(cut), 6, rep.notes)
        self.assertEqual(sorted(n.split(" ... (", 1)[1].split(" ")[0] for n in cut), ["1", "1", "1", "100", "100", "2"])
        self.assertTrue(all("zzHidden" not in n for n in rep.notes))      # cut away, but counted: "(2 in all"

    def test_a_list_that_fits_is_written_whole_and_unmarked(self):
        self.assertEqual(V.listed(["a" * 79, "b" * 79]), "a" * 79 + ", " + "b" * 79)       # 160 characters
        self.assertEqual(V.listed(["a" * 80, "b" * 79]), ("a" * 80 + ", " + "b" * 79)[:160]
                         + " ... (2 in all; list cut at 160 characters)")
        self.assertEqual(V.listed([]), "")

    def test_a_member_added_to_network_posture_is_not_named_when_no_record_binds_it(self):
        # what the comment above NESTED_MEMBERS states: with records the member moves the binding they must carry
        st, _ = B.scenario_artifact_only()
        st["predicate"]["observationEnvironment"]["networkPosture"]["uExtra"] = 1
        rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertFalse(any("uExtra" in n for n in rep.notes))
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["networkPosture"]["uExtra"] = 1
        self.assertEqual(Verifier(KEYS).verify_bytes(B.dumps(st)).to_json_line()["verdict"], "reject")


class TestNestedMembersAreNamed(unittest.TestCase):
    """Members of the objects inside the predicate that nothing reads were ignored in silence (N59 named only the
    statement, subject[0] and the predicate); guard: networkPosture and DigestSets are not named (passes on cbb79e5)."""

    def _objects(self, st):
        p = st["predicate"]
        env = p["observationEnvironment"]
        return {
            "observationEnvironment": env,
            "observationEnvironment.substrate": env["substrate"],
            "observationEnvironment.catchPolicy": env["catchPolicy"],
            "observationEnvironment.corpus": env["corpus"],
            "observationEnvironment.corpus.manifest": env["corpus"]["manifest"],
            "observationEnvironment.observationVocabulary": env["observationVocabulary"],
            "observationEnvironment.runEntropy": env["runEntropy"],
            "coverage": p["coverage"],
            "attackResults[]": p["attackResults"][2],
            "observationRecords[]": p["observationRecords"][1],
            "observationRecords[].signatures[]": p["observationRecords"][0]["signatures"][0],
        }

    def test_the_closed_lists_cover_every_object_the_builder_writes(self):
        st, _ = B.scenario_pass()
        self.assertEqual(set(self._objects(st)), set(V.NESTED_MEMBERS))
        rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertEqual([n for n in rep.notes if "ignored unrecognized" in n], [])

    def test_each_unread_member_is_named_and_the_verdict_does_not_move(self):
        rnd = random.Random(1120)
        for where in V.NESTED_MEMBERS:
            if where == "observationEnvironment.corpus.manifest":
                continue  # digest-pinned: an extra member is also a digest mismatch, tested below
            for _ in range(3):
                st, _ = B.scenario_pass()
                base = Verifier(KEYS).verify_bytes(B.dumps(st)).to_json_line()
                name = "u%08x" % rnd.getrandbits(32)
                obj = self._objects(st)[where]
                obj[name] = rnd.choice([None, 1, "x", [1], {"a": 1}])
                rep = Verifier(KEYS).verify_bytes(B.dumps(st))
                self.assertEqual(rep.to_json_line(), base, where)
                notes = [n for n in rep.notes if "ignored unrecognized %s member" % where in n]
                self.assertEqual(len(notes), 1, (where, rep.notes))
                self.assertIn(name, notes[0])

    def test_an_extra_manifest_member_is_named_beside_the_digest_check(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["uExtra"] = 1
        rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertIn("corpus-digest-mismatch", rep.code_set())
        self.assertTrue(any("corpus.manifest member" in n and "uExtra" in n for n in rep.notes), rep.notes)

    def test_network_posture_and_digest_sets_are_not_named(self):
        st, _ = B.scenario_pass()
        st["predicate"]["observationEnvironment"]["substrate"]["digest"]["sha512"] = "00"
        rep = Verifier(KEYS).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertEqual([n for n in rep.notes if "ignored unrecognized" in n], [])


class TestSignatureEntriesAreNamed(unittest.TestCase):
    """A signature entry that can verify nothing, or a keyid that is not a string, was skipped in silence; guard:
    well-formed entries are not named (passes on cbb79e5)."""

    def test_entries_that_verify_nothing_and_non_string_keyids_are_named(self):
        cases = [("@@", None), ("", None), (base64.b64encode(bytes(63)).decode(), None),
                 (base64.b64encode(bytes(65)).decode(), None), (None, {"k": 1}), (None, 7), (None, [B.SUBSTRATE_KEYID])]
        for sig, keyid in cases:
            st, _ = B.scenario_pass()
            base = Verifier(KEYS).verify_bytes(B.dumps(st)).to_json_line()
            rec = st["predicate"]["observationRecords"][1]
            extra = dict(rec["signatures"][0])
            if sig is not None:
                extra["sig"] = sig
            if keyid is not None:
                extra["keyid"] = keyid
            rec["signatures"] = [extra, rec["signatures"][0]] if keyid is None else [extra]
            rep = Verifier(KEYS).verify_bytes(B.dumps(st))
            self.assertEqual(rep.to_json_line(), base, (sig, keyid))
            what = "can verify nothing" if keyid is None else "keyid is not a string"
            self.assertTrue(any(what in n and " 1.0" in n for n in rep.notes), (sig, keyid, rep.notes))

    def test_well_formed_entries_are_not_named(self):
        rep = Verifier(KEYS).verify_bytes(B.dumps(B.scenario_pass()[0]))
        self.assertFalse(any("signature entr" in n for n in rep.notes), rep.notes)


def _forge_with_identity(st):
    s = 424242
    sig = base64.b64encode(ed25519._encode_point(ed25519._mul(s, ed25519._B)) + s.to_bytes(32, "little")).decode()
    for rec in st["predicate"]["observationRecords"]:
        rec["signatures"] = [{"keyid": "id", "sig": sig}]
    return st


class TestApiKeyPolicy(unittest.TestCase):
    """The key policy of N60 (keys of small or mixed order attest nothing) was applied by the CLI only, not by
    `Verifier`."""

    IDENTITY = bytes([1]) + bytes(31)

    def _mixed(self):
        A = ed25519._decode_point(B.SUBSTRATE_PUB)
        T2 = ed25519._decode_point(bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
        return ed25519._encode_point(ed25519._add(A, T2))

    def test_identity_key_attests_nothing_through_the_api(self):
        st = _forge_with_identity(B.scenario_pass()[0])
        rep = Verifier([("id", self.IDENTITY)]).verify_bytes(B.dumps(st))
        self.assertEqual(rep.to_json_line()["verdict"], "accept")
        self.assertEqual(rep.tiers, ["unattested"] * 3)
        self.assertTrue(any("small order" in n for n in rep.notes), rep.notes)

    def test_every_unusable_entry_is_skipped_and_named(self):
        self.assertEqual(ed25519.point_class(self._mixed()), "a point with a torsion component")
        st, _ = B.scenario_pass()
        bad = [("a", self.IDENTITY), ("b", self._mixed()), ("c", bytes(31)), ("d", "00" * 32), ("e", b"\xff" * 32),
               ("f",), ("g", B.SUBSTRATE_PUB, "x"), "h", None, ("i", "a" * 32), ("j", list(B.SUBSTRATE_PUB))]
        v = Verifier(bad)
        self.assertEqual(v.keys, [])
        rep = v.verify_bytes(B.dumps(st))
        self.assertEqual(rep.tiers, ["unattested"] * 3)
        self.assertEqual(len([n for n in rep.notes if n.startswith("key policy entry")]), len(bad))

    def test_good_key_still_attests_and_a_non_string_keyid_is_kept_and_named(self):
        st, _ = B.scenario_pass()
        for keyid in (B.SUBSTRATE_KEYID, 5, None):
            rep = Verifier([(keyid, B.SUBSTRATE_PUB)]).verify_bytes(B.dumps(st))
            self.assertEqual(rep.tiers, ["attested"] * 3, keyid)
            self.assertEqual(any("keyid is not a string" in n for n in rep.notes), not isinstance(keyid, str))
        rep = Verifier((("x", bytearray(B.SUBSTRATE_PUB)),)).verify_bytes(B.dumps(st))
        self.assertEqual(rep.tiers, ["attested"] * 3)

    def test_keys_of_another_type_are_refused(self):
        for keys in ("abc", {"k": B.SUBSTRATE_PUB}, 5, B.SUBSTRATE_PUB):
            with self.assertRaises(TypeError):
                Verifier(keys)


if __name__ == "__main__":
    unittest.main()
