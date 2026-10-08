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
from typing import List, Optional, Tuple

from .verifier import Verifier

ENV_KEYS = "AEE_SUBSTRATE_KEYS"


def load_key_policy(path: Optional[str], warn) -> Optional[List[Tuple[str, bytes]]]:
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
    except Exception as exc:  # fail-closed: no keys
        warn("%s=%r could not be read as JSON (%s); treating as no pinned key" % (ENV_KEYS, path, exc))
        return None
    keys: List[Tuple[str, bytes]] = []
    entries = doc.get("substrateObservationKeys") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        warn("%s: no substrateObservationKeys array; treating as no pinned key" % ENV_KEYS)
        return None
    for e in entries:
        if not isinstance(e, dict):
            continue
        hexkey = e.get("publicKeyHex")
        keyid = e.get("keyid")
        try:
            raw = bytes.fromhex(hexkey) if isinstance(hexkey, str) else b""
        except ValueError:
            raw = b""
        if len(raw) != 32:
            warn("%s: key %r is not a 32-byte (Ed25519) public key; skipped" % (ENV_KEYS, keyid))
            continue
        keys.append((keyid if isinstance(keyid, str) else "", raw))
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
        sys.stderr.write("warning: %s\n" % msg)

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
    except OSError as exc:
        sys.stderr.write("error: cannot read %s: %s\n" % (argv[0], exc))
        emit({"verdict": "error", "codes": ["unreadable-input"], "result": None, "tiers": []})
        return 2

    keys = load_key_policy(os.environ.get(ENV_KEYS), warn)
    report = Verifier(keys).verify_bytes(data)
    for note in report.notes:
        out.write("note: %s\n" % note)
    if report.rejected:
        for code, msg in report.codes:
            out.write("reject: %s: %s\n" % (code, msg))
    else:
        out.write("accept: result=%s tiers=%s (%s)\n" % (
            report.result, ",".join(report.tiers) or "-",
            "key policy: %d key(s)" % len(keys) if keys else "no pinned substrate key"))
    emit(report.to_json_line())
    return 1 if report.rejected else 0
