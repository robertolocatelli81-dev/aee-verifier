"""External vectors (tests/interop/SOURCES.md) and the key-policy rule N60.

* Wycheproof ed25519_test.json: 117 valid and 64 invalid cases give Wycheproof's answer under ed25519.verify; the 29
  "acceptable" ones (small- or mixed-order public keys) verify as signatures (RFC 8032 allows it); every key flagged
  SmallOrderPublicKey or MixedOrderPublicKey (30) is skipped with a warning by the key policy (N60), no other is.
* gowebpki/jcs testdata: jcs.canonicalize gives the expected bytes on all 10 cases.
"""

import glob
import json
import os
import random
import tempfile
import unittest

from aee_verifier import cli, ed25519, jcs

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "interop")
IDENTITY = bytes([1]) + bytes(31)


def wycheproof():
    with open(os.path.join(HERE, "wycheproof", "ed25519_test.json"), "rb") as fh:
        doc = json.load(fh)
    for g in doc["testGroups"]:
        pk = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            yield pk, t


def load(doc):
    warnings = []
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "k.json")
        with open(path, "w") as fh:
            fh.write(json.dumps(doc))
        keys = cli.load_key_policy(path, warnings.append)
    return keys, warnings


class TestWycheproof(unittest.TestCase):
    def test_signatures(self):
        seen = {"valid": 0, "invalid": 0, "acceptable": 0}
        for pk, t in wycheproof():
            got = ed25519.verify(pk, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]))
            seen[t["result"]] += 1
            if t["result"] == "valid":
                self.assertTrue(got, t["tcId"])
            elif t["result"] == "invalid":
                self.assertFalse(got, t["tcId"])
            else:
                self.assertTrue(got, t["tcId"])          # RFC 8032 equation holds; the key is the problem (N60)
        self.assertEqual(seen, {"valid": 117, "invalid": 64, "acceptable": 29})

    def test_policy_skips_every_flagged_key_and_keeps_every_other(self):
        weak, other = set(), set()
        for pk, t in wycheproof():
            flagged = {"SmallOrderPublicKey", "MixedOrderPublicKey"} & set(t["flags"])
            (weak if flagged else other).add(pk)
            if t["result"] == "acceptable":
                self.assertTrue(flagged, t["tcId"])
        self.assertEqual(len(weak), 30)          # the 29 acceptable keys + one mixed-order key whose case is invalid
        self.assertFalse(weak & other)
        for pk in sorted(weak):
            keys, warnings = load({"substrateObservationKeys": [{"keyid": "k", "publicKeyHex": pk.hex()}]})
            self.assertEqual(keys, [], pk.hex())
            self.assertEqual(len(warnings), 1)
            self.assertRegex(warnings[0], "small order|torsion")
        for pk in sorted(other):
            if ed25519._decode_point(pk) is None:
                continue                                  # not a point: verification already fails
            keys, warnings = load({"substrateObservationKeys": [{"keyid": "k", "publicKeyHex": pk.hex()}]})
            self.assertEqual(keys, [("k", pk)], pk.hex())
            self.assertEqual(warnings, [])

    def test_point_class_matches_the_wycheproof_flag(self):
        want = {"SmallOrderPublicKey": "a point of small order", "MixedOrderPublicKey": "a point with a torsion component"}
        counts = {}
        for pk, t in wycheproof():
            flag = [f for f in t["flags"] if f in want]
            got = ed25519.point_class(pk)
            if flag:
                self.assertEqual(got, want[flag[0]], t["tcId"])
                counts[flag[0]] = counts.get(flag[0], 0) + 1
            else:
                self.assertIn(got, ("prime-order", "not a point"), t["tcId"])
        self.assertEqual(counts, {"SmallOrderPublicKey": 8, "MixedOrderPublicKey": 22})
        for bad in (None, "", b"", bytes(31), bytes(33), bytearray(32), "00" * 32):
            self.assertEqual(ed25519.point_class(bad), "not a point")

    def test_identity_key_forges_and_is_skipped(self):
        s = 123456789
        sig = ed25519._encode_point(ed25519._mul(s, ed25519._B)) + s.to_bytes(32, "little")
        self.assertTrue(ed25519.verify(IDENTITY, b"any message", sig))      # the reason for N60
        keys, warnings = load({"substrateObservationKeys": [{"keyid": "id", "publicKeyHex": IDENTITY.hex()}]})
        self.assertEqual(keys, [])
        self.assertIn("small order", warnings[0])


class TestPolicyEntries(unittest.TestCase):
    PK = ed25519.public_key_from_seed(bytes(range(32))).hex()

    def test_each_unused_thing_is_named(self):
        keys, warnings = load({"substrateObservationKeys": [
            "not-an-object", 7, None, [1],
            {"keyid": 5, "publicKeyHex": self.PK},
            {"keyid": "x", "publicKeyHex": self.PK, "alg": "Ed25519", "note": 1}]})
        self.assertEqual(keys, [("", bytes.fromhex(self.PK)), ("x", bytes.fromhex(self.PK))])
        self.assertEqual(sum("not an object" in w for w in warnings), 4)
        self.assertEqual(sum("keyid" in w and "not a string" in w for w in warnings), 1)
        self.assertEqual(sum("'alg'" in w and "'note'" in w for w in warnings), 1)
        self.assertEqual(len(warnings), 6)

    def test_generated_entries_never_raise_and_never_keep_a_bad_key(self):
        rnd = random.Random(20261114)
        pool = [self.PK, IDENTITY.hex(), "zz" * 32, self.PK[:62], "", 3, None, [], {}, True, 1.5, self.PK.upper()]
        for _ in range(3000):
            entry = {}
            for k in rnd.sample(["keyid", "publicKeyHex", "x", "keyId", ""], rnd.randint(0, 4)):
                entry[k] = rnd.choice(pool + ["k"])
            doc = {"substrateObservationKeys": [entry if rnd.random() < 0.8 else rnd.choice(pool)]}
            keys, warnings = load(doc)
            for _, raw in keys:
                self.assertEqual(raw, bytes.fromhex(self.PK), doc)
            if not keys:
                self.assertTrue(warnings, doc)


    def test_duplicate_member_makes_the_policy_unusable(self):
        # N60: until 0d8cee1 the last of two equal names silently won (a key dropped out, or a weak one took its place)
        for text in ('{"substrateObservationKeys":[{"keyid":"k","publicKeyHex":"%s","publicKeyHex":"%s"}]}' % (self.PK, self.PK),
                     '{"substrateObservationKeys":[{"keyid":"k","publicKeyHex":"%s"}],"substrateObservationKeys":[]}' % self.PK,
                     '{"substrateObservationKeys":[{"keyid":"k","keyid":"k","publicKeyHex":"%s"}]}' % self.PK):
            warnings = []
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "k.json")
                with open(path, "w") as fh:
                    fh.write(text)
                self.assertIsNone(cli.load_key_policy(path, warnings.append), text)
            self.assertEqual(len(warnings), 1)
            self.assertIn("duplicate member", warnings[0])

    def test_top_level_member_and_non_point_key_are_named(self):
        not_a_point = (2 ** 255 - 19).to_bytes(32, "little").hex()          # y = p: no canonical point
        keys, warnings = load({"substrateObservationKeys": [{"keyid": "np", "publicKeyHex": not_a_point},
                                                            {"keyid": "k", "publicKeyHex": self.PK}], "comment": 1})
        self.assertEqual(keys, [("k", bytes.fromhex(self.PK))])
        self.assertEqual(len(warnings), 2)
        self.assertIn("'comment'", warnings[0])
        self.assertIn("'np' is not a point", warnings[1])


class TestJCSGowebpki(unittest.TestCase):
    def test_all_cases(self):
        names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(HERE, "gowebpki_jcs", "input", "*.json")))
        self.assertEqual(len(names), 10)
        for n in names:
            with open(os.path.join(HERE, "gowebpki_jcs", "input", n), "rb") as fh:
                value = json.loads(fh.read())
            with open(os.path.join(HERE, "gowebpki_jcs", "output", n), "rb") as fh:
                expected = fh.read()
            self.assertEqual(jcs.canonicalize(value), expected, n)


if __name__ == "__main__":
    unittest.main()
