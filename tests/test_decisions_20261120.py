"""Tests for the consumer policies decided on 2026-11-20 after the re-measure of the review findings (SPEC_NOTES N62
and after).  Each class names the decision and what was measured on 64227ea; every test fails on 64227ea except the
guards a class docstring names.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import builder as B  # noqa: E402
from aee_verifier import verifier as V  # noqa: E402
from aee_verifier.verifier import Verifier  # noqa: E402

KEYS = [(B.SUBSTRATE_KEYID, B.SUBSTRATE_PUB)]
UNREADABLE = '{"verdict":"error","codes":["unreadable-input"],"result":null,"tiers":[]}'
USAGE = '{"verdict":"error","codes":["usage"],"result":null,"tiers":[]}'


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


if __name__ == "__main__":
    unittest.main()
