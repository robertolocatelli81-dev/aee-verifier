"""Unit tests for the support modules, against the primary standards:
RFC 8785 (Appendix B numbers, section 3.2.3 sort vector, section 3.2.2
sample), RFC 7493 / RFC 8259 grammar, RFC 3339 calendar rules, RFC 8032
section 7.1 Ed25519 vectors.  Run: ``python3 tests/test_units.py``."""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from aee_verifier import cli, ed25519, timestamp  # noqa: E402
from aee_verifier.jcs import JCSError, canonicalize, format_number, utf16_key  # noqa: E402
from aee_verifier.strict_json import StrictJSONError, loads_strict  # noqa: E402

APPENDIX_B = {
    "0000000000000000": "0", "8000000000000000": "0", "0000000000000001": "5e-324", "8000000000000001": "-5e-324",
    "7fefffffffffffff": "1.7976931348623157e+308", "ffefffffffffffff": "-1.7976931348623157e+308",
    "4340000000000000": "9007199254740992", "c340000000000000": "-9007199254740992", "4430000000000000": "295147905179352830000",
    "44b52d02c7e14af5": "9.999999999999997e+22", "44b52d02c7e14af6": "1e+23", "44b52d02c7e14af7": "1.0000000000000001e+23",
    "444b1ae4d6e2ef4e": "999999999999999700000", "444b1ae4d6e2ef4f": "999999999999999900000", "444b1ae4d6e2ef50": "1e+21",
    "3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001", "41b3de4355555553": "333333333.3333332",
    "41b3de4355555554": "333333333.33333325", "41b3de4355555555": "333333333.3333333", "41b3de4355555556": "333333333.3333334",
    "41b3de4355555557": "333333333.33333343", "becbf647612f3696": "-0.0000033333333333333333",
}


class TestJCS(unittest.TestCase):
    def test_appendix_b_numbers(self):
        for hexbits, expected in APPENDIX_B.items():
            x = struct.unpack(">d", bytes.fromhex(hexbits))[0]
            self.assertEqual(format_number(x), expected, hexbits)

    def test_number_boundaries(self):
        cases = {1e21: "1e+21", 1e20: "100000000000000000000", 123456789012345680000.0: "123456789012345680000",
                 1e-7: "1e-7", 1e-6: "0.000001", 0.1: "0.1", 123.456: "123.456", -123.456: "-123.456",
                 1.5e-10: "1.5e-10", 2.5e22: "2.5e+22", 1.0: "1", 10.0: "10", -0.0: "0", 0.5: "0.5", 100.25: "100.25",
                 12345678901234567890.0: "12345678901234567000"}
        for x, expected in cases.items():
            self.assertEqual(format_number(x), expected, repr(x))
        self.assertEqual(format_number(0), "0")
        self.assertEqual(format_number(-7), "-7")
        self.assertEqual(format_number(9007199254740991), "9007199254740991")

    def test_number_errors(self):
        for bad in (float("nan"), float("inf"), float("-inf"), True, False):
            with self.assertRaises(JCSError):
                format_number(bad)

    def test_sort_vector_rfc8785_3_2_3(self):
        doc = (b'{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",'
               b'"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}')
        out = canonicalize(loads_strict(doc)).decode()
        self.assertEqual(list(json.loads(out).values()),
                         ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis",
                          "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"])
        # UTF-16 order differs from code-point order exactly on the emoji / Hebrew pair
        self.assertLess(utf16_key("\U0001F600"), utf16_key("דּ"))
        self.assertGreater("\U0001F600", "דּ")
        self.assertLess(utf16_key(""), utf16_key("a"))
        self.assertLess(utf16_key("a"), utf16_key("aa"))

    def test_sample_rfc8785_3_2_2(self):
        doc = (b'{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
               b' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", "literals": [null, true, false]}')
        expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        self.assertEqual(canonicalize(loads_strict(doc)).decode(), expected)

    def test_string_escapes(self):
        self.assertEqual(canonicalize("\b\t\n\f\r"), b'"\\b\\t\\n\\f\\r"')
        self.assertEqual(canonicalize("\x00\x01\x1f"), b'"\\u0000\\u0001\\u001f"')
        self.assertEqual(canonicalize('"\\/'), b'"\\"\\\\/"')
        self.assertEqual(canonicalize("\x7f é"), '"\x7f é"'.encode("utf-8"))
        self.assertEqual(canonicalize(" a b "), b'" a b "')  # U+0020 is not a control character
        self.assertEqual(canonicalize("\x1f\x20\x21"), b'"\\u001f !"')
        with self.assertRaises(JCSError):
            canonicalize("\ud800")

    def test_structures(self):
        self.assertEqual(canonicalize({}), b"{}")
        self.assertEqual(canonicalize([]), b"[]")
        self.assertEqual(canonicalize({"b": [1, {"d": None, "c": True}], "a": False}), b'{"a":false,"b":[1,{"c":true,"d":null}]}')
        with self.assertRaises(JCSError):
            canonicalize({1: 2})
        with self.assertRaises(JCSError):
            canonicalize(object())


class TestStrictJSON(unittest.TestCase):
    NEGATIVES = [
        (b'{"a":1,"a":2}', "duplicate"), (b'{"a":{"b":1,"b":2}}', "duplicate"), (b'"\\u+041"', "string"), (b'"\\u 041"', "string"),
        (b'"\\u1_23"', "string"), (b'"\\u004"', "string"), (b'"\\u004G"', "string"), (b'"\\ud800"', "string"), (b'"\\udc00"', "string"),
        (b'"\\ud800\\u0041"', "string"), (b'"\\ud800x"', "string"), (b'"\\ufdd0"', "string"), (b'"\\ufdef"', "string"),
        (b'"\\ufffe"', "string"), (b'"\\uffff"', "string"), (b'"\\ud83f\\udffe"', "string"), (b'"\xef\xb7\x90"', "string"),
        (b'"\xef\xbf\xbf"', "string"), (b'{"\\uffff":1}', "string"), (b'"\xed\xa0\x80"', "utf8"), (b'"\xc0\x80"', "utf8"),
        (b'"\xf4\x90\x80\x80"', "utf8"), (b'"\xff"', "utf8"), (b'"a\x01b"', "string"), (b'"a\x1fb"', "string"), (b'"a\nb"', "string"),
        (b'"\\x41"', "string"), (b'"\\a"', "string"), (b'"abc', "syntax"), (b'"abc\\', "syntax"),
        (b'9007199254740992', "integer"), (b'-9007199254740992', "integer"), (b'[9007199254740992]', "integer"),
        (b'1e400', "number"), (b'-1e400', "number"), (b'[' * 129 + b']' * 129, "depth"), (b'{"a":' * 129 + b'1' + b'}' * 129, "depth"),
        (b'{"a":1} x', "syntax"), (b'\xef\xbb\xbf{}', "syntax"), (b'01', "syntax"), (b'1.', "syntax"), (b'.5', "syntax"), (b'+1', "syntax"),
        (b'-', "syntax"), (b'1e', "syntax"), (b'1e+', "syntax"), (b'1.e5', "syntax"), (b'tru', "syntax"), (b'nul', "syntax"), (b'True', "syntax"),
        (b'NaN', "syntax"), (b'Infinity', "syntax"), (b'[1,]', "syntax"), (b'{"a":1,}', "syntax"), (b'{a:1}', "syntax"), (b'{"a" 1}', "syntax"),
        (b'{"a":1 "b":2}', "syntax"), (b'[1 2]', "syntax"), (b'', "syntax"), (b'  ', "syntax"), (b'{', "syntax"), (b'[', "syntax"),
        (b"'a'", "syntax"), (b'{"a":1]', "syntax"), (b'[1}', "syntax"), (b'\x0c{}', "syntax"),
    ]

    def test_negatives(self):
        for data, kind in self.NEGATIVES:
            with self.assertRaises(StrictJSONError, msg=data) as cm:
                loads_strict(data)
            self.assertEqual(cm.exception.kind, kind, data)

    def test_positives(self):
        cases = {
            b'9007199254740991': 9007199254740991, b'-9007199254740991': -9007199254740991, b'0': 0, b'-0': 0,
            b'1.0': 1.0, b'-0.0': -0.0, b'1e2': 100.0, b'1E+2': 100.0, b'1e-2': 0.01, b'0.5': 0.5, b'9007199254740992.0': 9007199254740992.0,
            b'"\\ud83d\\ude00"': "\U0001F600", b'"\xf0\x9f\x98\x80"': "\U0001F600", b'"\\ufdcf\\uff00\\ufffd"': "﷏＀�",
            b'"\\u0041\\u00e9\\/\\"\\\\\\b\\f\\n\\r\\t"': 'Aé/"\\\b\f\n\r\t', b'"\x7f\xe2\x80\xa8"': "\x7f ",
            b' \t\r\n{ "a" : [ 1 , 2.5 , true , false , null , "x" ] } \n': {"a": [1, 2.5, True, False, None, "x"]},
            b'{}': {}, b'[]': [], b'[[]]': [[]], b'{"":""}': {"": ""}, b'[' * 128 + b']' * 128: json.loads("[" * 128 + "]" * 128),
            b'{"a":' * 128 + b'1' + b'}' * 128: json.loads('{"a":' * 128 + '1' + '}' * 128),
        }
        for data, expected in cases.items():
            got = loads_strict(data)
            self.assertEqual(got, expected, data)
            self.assertEqual(type(got), type(expected), data)

    def test_depth_counts_open_containers_not_history(self):
        """Closing a container must restore the depth exactly: a sibling chain is measured on its own."""
        ok = b"[" + b"[" * 126 + b"]" * 126 + b"," + b"[" * 127 + b"]" * 127 + b"]"      # deepest point: 128
        bad = b"[" + b"[" * 126 + b"]" * 126 + b"," + b"[" * 128 + b"]" * 128 + b"]"     # deepest point: 129
        loads_strict(ok)
        with self.assertRaises(StrictJSONError) as cm:
            loads_strict(bad)
        self.assertEqual(cm.exception.kind, "depth")
        ok2 = b'{"a":' * 126 + b'{"b":[],"c":' + b'{"d":1}' + b'}' + b'}' * 126   # 126 + 2 = 128 at the deepest point, after closing "b"
        loads_strict(ok2)
        bad2 = b'{"a":' * 126 + b'{"b":[],"c":' + b'{"d":[1]}' + b'}' + b'}' * 126  # 129
        with self.assertRaises(StrictJSONError):
            loads_strict(bad2)
        # an object closed before the deepest sibling must restore the depth exactly
        ok3 = b'{"x":{},"y":' + b'[' * 127 + b']' * 127 + b'}'    # 1 + 127 = 128
        loads_strict(ok3)
        bad3 = b'{"x":{},"y":' + b'[' * 128 + b']' * 128 + b'}'   # 129
        with self.assertRaises(StrictJSONError) as cm:
            loads_strict(bad3)
        self.assertEqual(cm.exception.kind, "depth")

    def test_int_float_distinction(self):
        self.assertIs(type(loads_strict(b"1")), int)
        self.assertIs(type(loads_strict(b"1.0")), float)
        self.assertIs(type(loads_strict(b"1e0")), float)
        self.assertIs(type(loads_strict(b"true")), bool)

    def test_type_error(self):
        with self.assertRaises(TypeError):
            loads_strict("{}")

    def test_error_position(self):
        with self.assertRaises(StrictJSONError) as cm:
            loads_strict(b'{"a": 1, "a": 2}')
        self.assertEqual(cm.exception.kind, "duplicate")
        self.assertIn("duplicate member 'a'", str(cm.exception))


class TestTimestamp(unittest.TestCase):
    def test_valid(self):
        for v in ("2026-06-23T16:08:07Z", "2026-06-23T16:08:07+00:00", "2026-06-23T16:08:07-00:00", "2026-06-23T16:08:07.1Z",
                  "2026-06-23T16:08:07.123456789123Z", "2026-01-31T00:00:00Z", "2026-03-31T00:00:00Z", "2026-04-30T00:00:00Z",
                  "2026-05-31T00:00:00Z", "2026-06-30T00:00:00Z", "2026-07-31T00:00:00Z", "2026-08-31T00:00:00Z", "2026-09-30T00:00:00Z",
                  "2026-10-31T00:00:00Z", "2026-11-30T00:00:00Z", "2026-12-31T00:00:00Z", "2026-02-28T00:00:00Z", "2024-02-29T00:00:00Z",
                  "2000-02-29T00:00:00Z", "2026-06-23T23:59:59Z", "2026-06-23T23:59:60Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
            self.assertTrue(timestamp.is_valid(v), v)

    def test_invalid(self):
        for v in ("2026-06-23t16:08:07Z", "2026-06-23T16:08:07z", "2026-06-23T16:08:07+05:00", "2026-06-23T16:08:07+00:30",
                  "2026-06-23T16:08:07-01:00", "2026-06-23T16:08:07", "2026-06-23 16:08:07Z", "2026-06-23T16:08Z", "2026-6-23T16:08:07Z",
                  "2026-06-23T16:08:07.Z", "2026-06-23T16:08:07,5Z", " 2026-06-23T16:08:07Z", "2026-06-23T16:08:07Z ", "2026-06-23T16:08:07ZZ",
                  "2026-00-10T00:00:00Z", "2026-13-10T00:00:00Z", "2026-01-00T00:00:00Z", "2026-01-32T00:00:00Z", "2026-02-29T00:00:00Z",
                  "2023-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-02-30T00:00:00Z", "2024-02-30T00:00:00Z", "2000-02-30T00:00:00Z", "2026-03-32T00:00:00Z", "2026-04-31T00:00:00Z",
                  "2026-05-32T00:00:00Z", "2026-06-31T00:00:00Z", "2026-07-32T00:00:00Z", "2026-08-32T00:00:00Z", "2026-09-31T00:00:00Z",
                  "2026-10-32T00:00:00Z", "2026-11-31T00:00:00Z", "2026-12-32T00:00:00Z", "2026-06-23T24:00:00Z", "2026-06-23T16:60:07Z",
                  "2026-06-23T16:08:61Z", 1719160087, None, b"2026-06-23T16:08:07Z", ["2026-06-23T16:08:07Z"]):
            self.assertFalse(timestamp.is_valid(v), repr(v))

    def test_ordering(self):
        p = timestamp.parse_profile
        self.assertTrue(timestamp.not_later_than(p("2026-06-23T16:08:07Z"), p("2026-06-23T16:08:07Z")))
        self.assertTrue(timestamp.not_later_than(p("2026-06-23T16:08:07Z"), p("2026-06-23T16:08:07.000001Z")))
        self.assertFalse(timestamp.not_later_than(p("2026-06-23T16:08:07.000001Z"), p("2026-06-23T16:08:07Z")))
        self.assertEqual(p("2026-06-23T16:08:07.50Z"), p("2026-06-23T16:08:07.5+00:00"))
        self.assertEqual(p("2026-06-23T16:08:07.0Z"), p("2026-06-23T16:08:07-00:00"))
        self.assertTrue(timestamp.not_later_than(p("2026-06-23T16:08:07.9Z"), p("2026-06-23T16:08:08Z")))
        self.assertTrue(timestamp.not_later_than(p("2025-12-31T23:59:59Z"), p("2026-01-01T00:00:00Z")))
        self.assertFalse(timestamp.not_later_than(p("2026-01-01T00:00:00Z"), p("2025-12-31T23:59:59Z")))
        self.assertTrue(timestamp.not_later_than(p("2026-06-23T16:08:07.123Z"), p("2026-06-23T16:08:07.1230000000000000000000000000000000000000000000000000000000000000000001Z")))


RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk, pk, msg, sig in RFC8032:
            sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
            self.assertEqual(ed25519.public_key_from_seed(sk), pk)
            self.assertEqual(ed25519.sign(sk, msg), sig)
            self.assertTrue(ed25519.verify(pk, msg, sig))

    def test_rejections(self):
        sk, pk, msg, sig = (bytes.fromhex(x) for x in RFC8032[2])
        self.assertFalse(ed25519.verify(pk, msg + b"x", sig))
        self.assertFalse(ed25519.verify(pk, b"", sig))
        self.assertFalse(ed25519.verify(pk, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(ed25519.verify(pk, msg, bytes([sig[0] ^ 1]) + sig[1:]))
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + bytes([sig[32] ^ 1]) + sig[33:]))
        self.assertFalse(ed25519.verify(pk, msg, sig[:63]))
        self.assertFalse(ed25519.verify(pk, msg, sig + b"\x00"))
        self.assertFalse(ed25519.verify(pk[:31], msg, sig))
        self.assertFalse(ed25519.verify(pk + b"\x00", msg, sig))
        self.assertFalse(ed25519.verify(b"\x00" * 32, msg, sig))
        other_pk = bytes.fromhex(RFC8032[0][1])
        self.assertFalse(ed25519.verify(other_pk, msg, sig))
        # non-canonical scalar: s + L must be rejected even though it is the same residue
        s = int.from_bytes(sig[32:], "little")
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + (s + ed25519.L).to_bytes(32, "little")))
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + ed25519.L.to_bytes(32, "little")))
        # R with y >= p (0x7fff...ff with top bit clear is >= p) is not a valid point encoding
        bad_r = (ed25519.P).to_bytes(32, "little")
        self.assertFalse(ed25519.verify(pk, msg, bad_r + sig[32:]))
        # y = 2 has no square root for x on this curve
        self.assertFalse(ed25519.verify((2).to_bytes(32, "little"), msg, sig))
        # x = 0 with sign bit set is not canonical (y = 1 -> x = 0)
        self.assertFalse(ed25519.verify((1 | (1 << 255)).to_bytes(32, "little"), msg, sig))

    def test_point_decoding_rfc8032_5_1_3(self):
        # y >= p is not a valid encoding even though y mod p would be
        self.assertIsNone(ed25519._decode_point(ed25519.P.to_bytes(32, "little")))
        self.assertIsNone(ed25519._decode_point((ed25519.P + 1).to_bytes(32, "little")))
        self.assertIsNone(ed25519._decode_point(((1 << 255) - 1).to_bytes(32, "little")))
        # y = 1 is the neutral element (x = 0); with the sign bit set it is not a valid encoding
        neutral = ed25519._decode_point((1).to_bytes(32, "little"))
        self.assertIsNotNone(neutral)
        self.assertTrue(ed25519._equal(neutral, ed25519._NEUTRAL))
        self.assertIsNone(ed25519._decode_point((1 | (1 << 255)).to_bytes(32, "little")))
        # y = 2 is not on the curve
        self.assertIsNone(ed25519._decode_point((2).to_bytes(32, "little")))
        # the base point round-trips through encode/decode with both sign conventions distinct
        b = ed25519._B
        self.assertTrue(ed25519._equal(ed25519._decode_point(ed25519._encode_point(b)), b))
        neg_b = ((-b[0]) % ed25519.P, b[1], b[2], (-b[3]) % ed25519.P)
        self.assertFalse(ed25519._equal(b, neg_b))
        self.assertTrue(ed25519._equal(ed25519._decode_point(ed25519._encode_point(neg_b)), neg_b))
        self.assertTrue(ed25519._equal(ed25519._add(b, neg_b), ed25519._NEUTRAL))
        self.assertTrue(ed25519._equal(ed25519._mul(ed25519.L, b), ed25519._NEUTRAL))
        self.assertFalse(ed25519._equal(ed25519._mul(ed25519.L - 1, b), ed25519._NEUTRAL))

    def test_sign_verify_roundtrip_random(self):
        for i in range(8):
            seed = bytes([i] * 32)
            msg = bytes(range(i * 13 % 251))
            pk = ed25519.public_key_from_seed(seed)
            sig = ed25519.sign(seed, msg)
            self.assertTrue(ed25519.verify(pk, msg, sig))
            self.assertFalse(ed25519.verify(pk, msg + b"\x00", sig))

    def test_against_cryptography_if_available(self):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:  # the oracle is optional
            self.skipTest("cryptography not installed")
        for i in range(6):
            seed = os.urandom(32)
            k = Ed25519PrivateKey.from_private_bytes(seed)
            pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            msg = os.urandom(i * 11)
            self.assertEqual(ed25519.public_key_from_seed(seed), pub)
            self.assertEqual(ed25519.sign(seed, msg), k.sign(msg))
            self.assertTrue(ed25519.verify(pub, msg, k.sign(msg)))


class TestKeyPolicy(unittest.TestCase):
    def load(self, doc):
        warnings = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.json")
            with open(path, "w") as fh:
                fh.write(doc if isinstance(doc, str) else json.dumps(doc))
            keys = cli.load_key_policy(path, warnings.append)
        return keys, warnings

    def test_good_policy(self):
        pk = RFC8032[0][1]
        keys, warnings = self.load({"substrateObservationKeys": [{"keyid": "a", "publicKeyHex": pk}, {"keyid": "b", "publicKeyHex": pk.upper()}]})
        self.assertEqual(keys, [("a", bytes.fromhex(pk)), ("b", bytes.fromhex(pk))])
        self.assertEqual(warnings, [])

    def test_bad_entries_skipped(self):
        pk = RFC8032[0][1]
        keys, warnings = self.load({"substrateObservationKeys": [
            {"keyid": "short", "publicKeyHex": pk[:62]}, {"keyid": "nothex", "publicKeyHex": "zz" * 32}, {"keyid": "none"},
            "not-a-dict", {"keyid": 5, "publicKeyHex": pk}]})
        self.assertEqual(keys, [("", bytes.fromhex(pk))])
        self.assertEqual(len(warnings), 3)

    def test_unusable_policy_is_no_policy(self):
        for doc in ("not json", {"keys": []}, [1, 2]):
            keys, warnings = self.load(doc)
            self.assertIsNone(keys)
            self.assertEqual(len(warnings), 1)
        self.assertIsNone(cli.load_key_policy(None, lambda m: None))
        self.assertIsNone(cli.load_key_policy("", lambda m: None))
        warnings = []
        self.assertIsNone(cli.load_key_policy("/nonexistent/keys.json", warnings.append))
        self.assertEqual(len(warnings), 1)

    def test_empty_key_list(self):
        keys, warnings = self.load({"substrateObservationKeys": []})
        self.assertEqual(keys, [])


class TestCLIUsage(unittest.TestCase):
    def test_usage(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        for argv in ([], ["a", "b"], ["--help"]):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = cli.main(argv)
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["verdict"], "error")
            self.assertIn("usage", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=1)
