"""Command line: ``python3 -m aee_verifier <statement.json>``.

Output contract (agent-evidence-vectors 0.12.1 README, "What the suite
compares"): the LAST line of stdout is one JSON object
``{"verdict": ..., "codes": [...], "result": ..., "tiers": [...],
"primaryCode": ...}`` on a single line; the exit status carries the verdict
(0 = accept, 1 = reject, 2 = the verifier could not run: unreadable input or
bad invocation).  Human-readable lines precede the JSON line.

The consumer key policy is read from the file named by the environment
variable ``AEE_SUBSTRATE_KEYS``: ``{"substrateObservationKeys": [{"keyid":
..., "publicKeyHex": ...}]}``.  Unset means no pinned substrate root: every
``basis: substrate`` row derives ``unattested`` and nothing is inferred from
the predicate.  A set but unusable policy file is treated the same way
(fail-closed) and a warning is written to stderr.
"""

from __future__ import annotations

import json
import os
import sys
import unicodedata
from typing import List, Optional, Tuple

from . import ed25519
from .verifier import Verifier

ENV_KEYS = "AEE_SUBSTRATE_KEYS"
ENTRY_MEMBERS = ("keyid", "publicKeyHex")


def one_line(text: str) -> str:
    """Text of one human-readable output line, with every character that could end or rewrite a line escaped.

    Notes and messages quote statement text (member names, values): a member name holding "\n" printed as is
    started a new line of the attacker's choosing, e.g. a forged ``accept:`` line or a forged JSON object above the
    real last line (measured on cbb79e5, 2026-11-20).  Closed list: Unicode categories Cc (C0/C1 controls, among
    them CR, LF, VT, FF, ESC, NEL), Zl (U+2028) and Zp (U+2029) -- every line boundary of str.splitlines -- are
    written as \\xNN or \\uNNNN; nothing else is changed."""
    out = []
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            o = ord(ch)
            out.append("\\x%02x" % o if o < 0x100 else "\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def _no_duplicate_members(pairs):
    names = [k for k, _ in pairs]
    dup = sorted(set(k for k in names if names.count(k) > 1))
    if dup:                                # N60: RFC 7493 2.3, as strict_json does for the statement
        raise ValueError("duplicate member(s) %s" % ", ".join(repr(k) for k in dup))
    return dict(pairs)


def load_key_policy(path: Optional[str], warn) -> Optional[List[Tuple[str, bytes]]]:
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"), object_pairs_hook=_no_duplicate_members)
    except Exception as exc:  # fail-closed: no keys
        warn("%s=%r could not be read as JSON (%s); treating as no pinned key" % (ENV_KEYS, path, exc))
        return None
    keys: List[Tuple[str, bytes]] = []
    entries = doc.get("substrateObservationKeys") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        warn("%s: no substrateObservationKeys array; treating as no pinned key" % ENV_KEYS)
        return None
    top = sorted(k for k in doc if k != "substrateObservationKeys")
    if top:                                # N60: named, never ignored in silence
        warn("%s: member(s) %s not read" % (ENV_KEYS, ", ".join(repr(k) for k in top)))
    for n, e in enumerate(entries):
        if not isinstance(e, dict):        # N60: named, never skipped in silence
            warn("%s: entry %d is not an object; skipped" % (ENV_KEYS, n))
            continue
        extra = sorted(k for k in e if k not in ENTRY_MEMBERS)
        if extra:
            warn("%s: entry %d: member(s) %s not read" % (ENV_KEYS, n, ", ".join(repr(k) for k in extra)))
        hexkey = e.get("publicKeyHex")
        keyid = e.get("keyid")
        try:
            raw = bytes.fromhex(hexkey) if isinstance(hexkey, str) else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            warn("%s: key %r is not a 32-byte (Ed25519) public key; skipped" % (ENV_KEYS, keyid))
            continue
        weak = ed25519.point_class(raw)
        if weak != "prime-order":          # N60: a key of small or mixed order attests nothing
            warn("%s: key %r is %s; skipped (SPEC_NOTES N60)" % (ENV_KEYS, keyid, weak))
            continue
        if not isinstance(keyid, str):
            warn("%s: entry %d: keyid %r is not a string; key kept with no keyid hint" % (ENV_KEYS, n, keyid))
            keyid = ""
        keys.append((keyid, raw))
    return keys


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = sys.stdout
    # Human-readable lines quote statement text; on a stdout whose encoding
    # cannot represent it, escape rather than die before the JSON line.
    try:
        out.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    def warn(msg: str) -> None:
        sys.stderr.write("warning: %s\n" % one_line(msg))

    def emit(obj: dict) -> None:
        out.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
        out.flush()

    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        sys.stderr.write("usage: python3 -m aee_verifier <statement.json>\n")
        emit({"verdict": "error", "codes": ["usage"], "result": None, "tiers": []})
        return 2
    try:
        with open(argv[0], "rb") as fh:
            data = fh.read()
    except (OSError, MemoryError) as exc:
        # MemoryError: an input larger than the memory the process may use (an endless device such as /dev/zero,
        # or a huge file) ended in a traceback, exit 1 -- the reject status -- and no JSON line (measured on
        # cbb79e5 under ulimit -v 600000, 2026-11-20); it is input the verifier could not read: exit 2, as documented.
        sys.stderr.write(one_line("error: cannot read %s: %s" % (argv[0], exc if str(exc) else type(exc).__name__)) + "\n")
        emit({"verdict": "error", "codes": ["unreadable-input"], "result": None, "tiers": []})
        return 2

    keys = load_key_policy(os.environ.get(ENV_KEYS), warn)
    report = Verifier(keys).verify_bytes(data)
    for note in report.notes:
        out.write("note: %s\n" % one_line(note))
    if report.rejected:
        for code, msg in report.codes:
            out.write("reject: %s: %s\n" % (one_line(code), one_line(msg)))
    else:
        out.write("accept: result=%s tiers=%s (%s)\n" % (
            report.result, ",".join(report.tiers) or "-",
            "key policy: %d key(s)" % len(keys) if keys else "no pinned substrate key"))
    emit(report.to_json_line())
    return 1 if report.rejected else 0
