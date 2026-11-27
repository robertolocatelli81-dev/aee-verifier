"""A secret given to the verifier does not come out of it (SPEC_NOTES N66, 2026-11-27).

The inputs, counted with grep on 0.2.0 (os.environ, open, sys.argv in aee_verifier/): the statement path and its bytes,
AEE_SUBSTRATE_KEYS (a path) and the key policy file it names, AEE_MAX_INPUT_BYTES, AEE_MAX_SIGNATURES_PER_RECORD,
AEE_MAX_FAILED_VERIFICATIONS. The statement is the public evidence the verifier is asked about, and its member names are
quoted on purpose (N61); the inputs that can carry a secret are the key policy (a private key or key file given where the
policy goes, a private member in an entry, a key where a name or keyid goes), the value of AEE_SUBSTRATE_KEYS (a key set
where the path goes) and the values of the three limits. A canary goes into each and is searched in everything that comes
out: stdout and stderr of the command line, the warnings of load_key_policy, the files left in the folder, and, through
an audit hook, any process started, any connection and any file opened for writing (there must be none). Searched raw,
in hex, HEX, decimal, base64 and base64url at each offset, and as any 12-character piece of the raw and hex forms.
Positive control: the search finds each form, and the hook sees a process, a connection and a write. The tests marked
"fails on 0.2.0" fail on the code of the tag v0.2.0 (the package files of the PyPI wheel are the same)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from aee_verifier import cli, ed25519  # noqa: E402

SEED = hashlib.sha256(b"aee-verifier test_secrets canary seed").digest()        # a test key, not anyone's
KEYNAME = SEED.hex()                                                              # 64 characters: a key where a name goes
TOKEN = "tk_" + base64.urlsafe_b64encode(hashlib.sha256(b"token" + SEED).digest()).decode().rstrip("=")
CANARIES = (SEED, KEYNAME.encode(), TOKEN.encode())
PUB = ed25519.public_key_from_seed(hashlib.sha256(b"a public key" + SEED).digest()).hex()
PY = [sys.executable, "-B"]
# N66: the private members of a JWK, RFC 7518 6.2.2.1, 6.3.2, 6.4.1 and RFC 8037 2 (written here, not read from cli)
PRIVATE_MEMBERS = ("d", "dp", "dq", "k", "oth", "p", "q", "qi")
NAME_CHARS = 32                                                      # N66

# the private key as files are written: raw seed, hex, PKCS#8 PEM (RFC 8410 prefix), private JWK (RFC 8037)
PEM = ("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n"
       % base64.b64encode(bytes.fromhex("302e020100300506032b657004220420") + SEED).decode())
JWK = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(ed25519.public_key_from_seed(SEED)).decode()
       .rstrip("="), "d": base64.urlsafe_b64encode(SEED).decode().rstrip("=")}

# run inside the child: an audit hook records every process, connection and write open, then the command line runs
HOOKED = r"""
import os, sys
seen = []
WRITE = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT
def hook(event, args):
    if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile",
                 "socket.connect", "socket.getaddrinfo"):
        seen.append(event)
    elif event == "open" and len(args) > 2:
        mode, flags = args[1], args[2]
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & WRITE):
            seen.append("open-write")
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[1])
from aee_verifier import cli
rc = cli.main(sys.argv[3:]) if sys.argv[2] == "verify" else None
if sys.argv[2] == "control":
    import socket, subprocess, tempfile
    subprocess.run([sys.executable, "-c", "pass"])
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=1)
    except OSError:
        pass
    with tempfile.TemporaryFile("w") as f:
        f.write("x")
    rc = 0
sys.stderr.write("\nHOOK:%s\n" % ",".join(sorted(set(seen))))
sys.exit(rc)
"""


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    for name, text in (("raw", secret), ("hex", secret.hex().encode())):   # a message cut at a length keeps a piece
        for i in range(0, len(text) - 12 + 1):
            out["%s[%d:]" % (name, i)] = text[i:i + 12]
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")      # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="aeesec-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.inputs = set()
        self.statement = self.file("statement.json", json.dumps({"_type": "https://in-toto.io/Statement/v1"}))

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        self.inputs.add(os.path.abspath(p))
        return p

    def policy(self, name, doc):
        return self.file(name, doc if isinstance(doc, (bytes, str)) else json.dumps(doc))

    def left(self):
        out = []
        for base, _, files in os.walk(self.d):
            for n in files:
                p = os.path.join(base, n)
                if os.path.abspath(p) not in self.inputs:
                    with open(p, "rb") as f:
                        out.append(p.encode() + b"\n" + f.read())
        return out

    def cli(self, env, *argv, mode="verify"):
        """the command line in a child with the audit hook; the environment holds only what the test sets"""
        full = {k: v for k, v in os.environ.items() if not k.startswith("AEE_")}
        full.update(env)
        r = subprocess.run(PY + ["-c", HOOKED, ROOT, mode] + list(argv or [self.statement]), capture_output=True,
                           timeout=120, cwd=self.d, env=full, stdin=subprocess.DEVNULL)
        err = r.stderr.decode("utf-8", "replace")
        hook = err.rsplit("HOOK:", 1)[1].strip() if "HOOK:" in err else "missing"
        return r, hook

    def none(self, what, env, *argv):
        r, hook = self.cli(env, *argv)
        self.assertIn(r.returncode, (0, 1, 2), (what, r.stderr[-300:]))
        self.assertTrue(r.stdout.strip().splitlines()[-1].startswith(b"{"), what)     # the JSON line is still there
        self.assertEqual(hook, "", (what, "a process, connection or write"))
        for c in CANARIES:
            self.assertEqual(found(c, r.stdout, r.stderr, *self.left()), [], (what, r.stderr[-400:]))
        return r

    def warnings(self, path):
        w = []
        keys = cli.load_key_policy(path, w.append)
        for c in CANARIES:
            self.assertEqual(found(c, *w), [], w)
        return keys, w


class TestPositiveControl(Base):
    def test_the_search_finds_every_form(self):
        for c in CANARIES:
            for name, f in forms(c).items():
                self.assertIn(name, found(c, b"<" + f + b">"), name)
            self.assertEqual(found(c, b"nothing of it"), [])
        self.assertIn("hex", found(SEED, "cut: %r" % KEYNAME))      # the way 0.2.0 wrote a name

    def test_the_hook_sees_a_process_a_connection_and_a_write(self):
        r, hook = self.cli({}, mode="control")
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        for e in ("subprocess.Popen", "socket.connect", "open-write"):
            self.assertIn(e, hook.split(","))

    def test_left_sees_a_file_written(self):
        with open(os.path.join(self.d, "out.txt"), "wb") as f:
            f.write(SEED)
        self.assertNotEqual(found(SEED, *self.left()), [])


class TestKeyPolicyCommandLine(Base):
    def test_a_key_set_where_the_path_goes(self):                         # fails on 0.2.0
        self.none("AEE_SUBSTRATE_KEYS=<key>", {"AEE_SUBSTRATE_KEYS": KEYNAME})
        self.none("AEE_SUBSTRATE_KEYS=<token>", {"AEE_SUBSTRATE_KEYS": TOKEN})
        for key in (KEYNAME, TOKEN):        # a key typed where the statement path goes (N66)
            r = self.none("argv=<key>", {}, key)
            self.assertEqual(r.returncode, 2)
            self.assertIn(b"cannot read the statement (a path of %d characters): FileNotFoundError (ENOENT)" % len(key),
                          r.stderr)

    def test_a_private_key_file_where_the_policy_goes(self):
        for name, data in (("seed.bin", SEED), ("seed.hex", KEYNAME), ("key.pem", PEM), ("key.jwk", json.dumps(JWK)),
                           ("seed.b64", base64.b64encode(SEED))):
            self.none(name, {"AEE_SUBSTRATE_KEYS": self.policy(name, data)})

    def test_a_key_where_a_name_or_keyid_goes(self):                      # fails on 0.2.0
        cases = {
            "top member": {"substrateObservationKeys": [], KEYNAME: 1},
            "entry member": {"substrateObservationKeys": [{"keyid": "k", "publicKeyHex": PUB, KEYNAME: 1}]},
            "keyid, bad key": {"substrateObservationKeys": [{"keyid": KEYNAME, "publicKeyHex": "00"}]},
            "keyid, weak key": {"substrateObservationKeys": [{"keyid": KEYNAME, "publicKeyHex": "00" * 32}]},
            "keyid not a string": {"substrateObservationKeys": [{"keyid": [KEYNAME, TOKEN], "publicKeyHex": PUB}]},
            "duplicate": '{"substrateObservationKeys": [], "%s": 1, "%s": 2}' % (KEYNAME, KEYNAME),
        }
        for n, (what, doc) in enumerate(cases.items()):
            self.none(what, {"AEE_SUBSTRATE_KEYS": self.policy("p%d.json" % n, doc)})

    def test_a_private_member_in_an_entry(self):
        jwk = dict(JWK, keyid="k", publicKeyHex=PUB)
        self.none("private JWK entry", {"AEE_SUBSTRATE_KEYS": self.policy("p.json", {"substrateObservationKeys": [jwk]})})


class TestLimitsAndEnvironment(Base):
    def test_a_secret_in_a_limit_variable(self):                           # fails on 0.2.0
        for var in (cli.ENV_MAX_INPUT, cli.ENV_MAX_SIGNATURES, cli.ENV_MAX_FAILED):
            for value in (KEYNAME, TOKEN):
                r = self.none(var, {var: value})
                self.assertEqual(r.returncode, 2)
                self.assertIn(var.encode(), r.stderr)                    # the variable is still named
            r = self.none(var + "=0...0", {var: "0" * 40})               # digits, below 1: the other refusal
            self.assertIn(b"%s is not a positive decimal integer (a value of 40 characters)" % var.encode(), r.stderr)

    def test_a_secret_elsewhere_in_the_environment(self):
        self.none("environment", {"SOME_SERVICE_TOKEN": TOKEN, "SIGNING_KEY": KEYNAME})


class TestKeyPolicyLibrary(Base):
    def test_a_private_member_refuses_the_entry(self):                     # fails on 0.2.0
        for m in PRIVATE_MEMBERS:
            path = self.policy("p_%s.json" % m, {"substrateObservationKeys": [{"keyid": "k", "publicKeyHex": PUB,
                                                                               m: JWK["d"]}]})
            keys, w = self.warnings(path)
            self.assertEqual(keys, [], m)
            self.assertTrue(any("private key member(s) %r" % m in x for x in w), w)

    def test_without_a_private_member_the_key_is_kept(self):               # the guard: nothing over-refused
        path = self.policy("ok.json", {"substrateObservationKeys": [{"keyid": "k", "publicKeyHex": PUB, "kid": "x"}]})
        keys, w = self.warnings(path)
        self.assertEqual(keys, [("k", bytes.fromhex(PUB))])
        self.assertEqual(w, ["AEE_SUBSTRATE_KEYS: entry 0: member(s) 'kid' not read"])

    def test_the_reason_is_its_type_not_its_text(self):                    # fails on 0.2.0
        _, w = self.warnings(self.policy("seed.bin", b"\xff" + SEED))   # 0.2.0 wrote "can't decode byte 0xff ..."
        self.assertEqual(w, ["AEE_SUBSTRATE_KEYS (a path of %d characters) could not be read as JSON "
                             "(UnicodeDecodeError); treating as no pinned key" % len(os.path.join(self.d, "seed.bin"))])
        _, w = self.warnings(os.path.join(self.d, KEYNAME))
        self.assertIn("(FileNotFoundError (ENOENT))", w[0])
        _, w = self.warnings(self.policy("bad.json", "{\n  x"))
        self.assertIn("(JSONDecodeError at line 2 column 3)", w[0])
        # read under the limit of the statement (N62): a larger file, or an endless device, stops there
        big = self.policy("big.json", b"")
        with open(big, "r+b") as f:
            f.truncate(cli.MAX_INPUT_BYTES + 1)
        _, w = self.warnings(big)
        self.assertIn("(InputTooLarge)", w[0])

    def test_short_names_are_still_shown(self):         # fails on 0.2.0 (the long name whole); the guard: the diagnosis stays
        name = "n" * NAME_CHARS
        _, w = self.warnings(self.policy("s.json", {"substrateObservationKeys": [], name: 1, name + "x": 2}))
        self.assertEqual(w, ["AEE_SUBSTRATE_KEYS: member(s) %r, a name of %d characters not read"
                             % (name, NAME_CHARS + 1)])
        # a keyid shown by its length only: the entry is still named by its index
        _, w = self.warnings(self.policy("e.json", {"substrateObservationKeys": [
            {"keyid": "k", "publicKeyHex": PUB}, {"keyid": KEYNAME, "publicKeyHex": "00"},
            {"keyid": KEYNAME, "publicKeyHex": "00" * 32}]}))
        self.assertEqual(w, ["AEE_SUBSTRATE_KEYS: entry 1: key a name of 64 characters is not a 32-byte (Ed25519) "
                             "public key; skipped",
                             "AEE_SUBSTRATE_KEYS: entry 2: key a name of 64 characters is a point of small order; skipped "
                             "(SPEC_NOTES N60)"])


if __name__ == "__main__":
    unittest.main()
