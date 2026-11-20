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


if __name__ == "__main__":
    unittest.main()
