"""Verifier for the in-toto predicate "Adversarial Execution Evidence" 0.7.0
(type URI .../adversarial-execution-evidence/v0.7), built from the spec text
at agent-evidence-vectors v0.12.1 and nothing else.

Structure (spec "Parsing Rules"): stage one is byte-pure -- statement
well-formedness, coverage validity, the ``result`` recompute, digest
integrity; stage two is trust-relative -- the per-row evidence tier against
the consumer key policy.  Every condition this verifier can name is
recorded as a code (this module's own vocabulary: the spec defines none) and
a message; any code makes the verdict ``reject``.

The checks are grouped in phases.  A phase that finds a defect the next
phase would only cascade on stops the walk; independent defects within a
phase are all reported.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import ed25519, timestamp
from .jcs import canonicalize, utf16_key
from .strict_json import StrictJSONError, loads_strict

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
BINDING_VERSION = "2"
IN_TOTO_ENVELOPE_TYPE = "application/vnd.in-toto+json"

RESULTS = ("fail", "degraded", "pass_indirect", "pass")  # ascending order
BASIS_VOCAB = ("substrate", "artifact")
METHOD_VOCAB = ("intercepted", "reconstructed")
ATTRIBUTION_VOCAB = ("pinned", "paired")
POSTURE_VOCAB = ("allowlist", "no_network", "sinkhole", "unsafe_bypass_egress")
CHAIN_SCOPE_VOCAB = ("subject", "corpus", "networkPosture")
COVERING_KINDS = ("interception", "arming", "sealed", "examination")
NON_COVERING_REGISTERED = ("moat-drop", "uncommitted-observation")
RETIRED_SPELLINGS = ("does_not_assert", "interceptRecords", "interceptRefs")

# Reserved payload members this verifier recognises.  Any other member whose
# name begins with ``aee`` is an unrecognised reserved member: fail-closed,
# the record covers nothing (spec, "Precedent" paragraph).
KNOWN_RESERVED = {
    "aeeRunBinding", "aeeKind", "aeeMethod",
    "aeePayloadCommitment",
    "aeeAssessedAttacks", "aeePostureDigest", "armedAt",
    "aeeStillArmed", "aeeDropCount", "aeeDropBound", "aeeObservedSet", "aeeObservedAttacks",
    "aeeRunSeq", "aeePrevRunBinding", "aeeChainScope", "aeeBindingVersion",
    "aeeVersion",
}

# \Z, not $: in Python ``$`` also matches before a final "\n".
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and _HEX64.match(v) is not None


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def is_bmp(s: str) -> bool:
    return all(ord(ch) <= 0xFFFF for ch in s)


def sorted_unique_strings(arr: Any) -> bool:
    """Array of strings, sorted ascending by UTF-16 code unit, no duplicates."""
    if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
        return False
    keys = [utf16_key(x) for x in arr]
    return all(keys[i] < keys[i + 1] for i in range(len(keys) - 1))


def decode_base64(s: Any) -> Optional[bytes]:
    """DSSE: standard or URL-safe alphabet, padding optional; invalid -> None."""
    if not isinstance(s, str) or s == "":
        return None if not isinstance(s, str) else b""
    if re.match(r"[A-Za-z0-9+/]*={0,2}\Z", s):
        alphabet = None
    elif re.match(r"[A-Za-z0-9_-]*={0,2}\Z", s):
        alphabet = b"-_"
    else:
        return None
    body = s.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        return base64.b64decode(padded, altchars=alphabet, validate=True)
    except Exception:
        return None


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + b" " + payload


def merkle_root(leaves: List[bytes]) -> Optional[str]:
    """RFC 6962 root (recursive split, no padding) over precomputed leaf hashes."""
    if not leaves:
        return None

    def node(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return leaves[lo]
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + node(lo, lo + k) + node(lo + k, hi)).digest()

    return node(0, len(leaves)).hex()


class Record:
    """One carried observation record and everything derived from it."""

    def __init__(self, index: int):
        self.index = index
        self.pae: Optional[bytes] = None
        self.leaf: Optional[bytes] = None
        self.payload_type: Optional[str] = None
        self.payload_bytes: Optional[bytes] = None
        self.signatures: list = []
        self.parsed: Optional[dict] = None
        self.parse_problem: Optional[str] = None  # why the payload is not a canonical +json object
        self.kind: Optional[str] = None            # aeeKind when a string
        self.binding: Optional[str] = None         # aeeRunBinding when a string
        self.method: Optional[str] = None          # aeeMethod when in vocabulary
        self.reserved_ok = False                   # aeeRunBinding/aeeKind strings, aeeMethod in vocab
        self.kind_problems: List[str] = []         # constraint violations of its kind
        self.binding_version_problem = False
        self.observed_set_mismatch = False
        self.unrecognised_reserved: List[str] = []

    @property
    def covering_kind(self) -> bool:
        return self.kind in COVERING_KINDS

    @property
    def usable(self) -> bool:
        return self.parsed is not None and self.parse_problem is None and self.reserved_ok

    @property
    def kind_valid(self) -> bool:
        """Satisfies every constraint of its declared covering kind."""
        return (self.usable and self.covering_kind and not self.kind_problems
                and not self.binding_version_problem and not self.unrecognised_reserved)


class Report:
    def __init__(self):
        self.codes: List[Tuple[str, str]] = []
        self.result: Optional[str] = None
        self.tiers: List[str] = []
        self.primary: Optional[str] = None
        self.notes: List[str] = []

    def fail(self, code: str, message: str) -> None:
        self.codes.append((code, message))

    @property
    def rejected(self) -> bool:
        return bool(self.codes)

    def code_set(self) -> List[str]:
        seen: List[str] = []
        for c, _ in self.codes:
            if c not in seen:
                seen.append(c)
        return seen

    def to_json_line(self) -> dict:
        codes = self.code_set()
        primary = self.primary or (codes[0] if codes else None)
        out = {
            "verdict": "reject" if self.rejected else "accept",
            "codes": codes,
            "result": None if self.rejected else self.result,
            "tiers": [] if self.rejected else self.tiers,
        }
        if primary is not None:
            out["primaryCode"] = primary
        return out


class Verifier:
    def __init__(self, keys: Optional[List[Tuple[str, bytes]]] = None):
        # keys: list of (keyid, raw ed25519 public key bytes); None = no policy
        self.keys = keys

    # ------------------------------------------------------------------ entry
    def verify_bytes(self, data: bytes) -> Report:
        rep = Report()
        statement = self._parse_statement_bytes(data, rep)
        if statement is None:
            return rep
        self._verify_statement(statement, rep)
        return rep

    # ------------------------------------------------------------- phase 0/1
    def _parse_json(self, data: bytes, rep: Report, what: str):
        try:
            return loads_strict(data)
        except StrictJSONError as exc:
            code = {
                "utf8": "invalid-utf8",
                "duplicate": "duplicate-member",
                "depth": "nesting-depth-exceeded",
                "string": "ill-formed-string",
                "integer": "integer-out-of-safe-range",
                "number": "number-out-of-range",
            }.get(exc.kind, "malformed-json")
            rep.fail(code, "%s: %s" % (what, exc))
            return None

    def _parse_statement_bytes(self, data: bytes, rep: Report):
        value = self._parse_json(data, rep, "statement")
        if value is None:
            return None
        if not isinstance(value, dict):
            rep.fail("statement-not-object", "the JSON text is not an object")
            return None
        # A DSSE envelope wrapping the statement is unwrapped; its signature is
        # not verified (no envelope key policy is defined for this harness).
        if ("payload" in value and "payloadType" in value and "signatures" in value
                and "_type" not in value and "predicateType" not in value):
            if value.get("payloadType") != IN_TOTO_ENVELOPE_TYPE:
                rep.fail("envelope-payload-type", "DSSE envelope payloadType is not %s" % IN_TOTO_ENVELOPE_TYPE)
                return None
            inner = decode_base64(value.get("payload"))
            if inner is None:
                rep.fail("envelope-payload-not-base64", "DSSE envelope payload is not base64")
                return None
            rep.notes.append("input was a DSSE envelope; envelope signature not verified (no envelope key policy)")
            value = self._parse_json(inner, rep, "statement (envelope payload)")
            if value is None:
                return None
            if not isinstance(value, dict):
                rep.fail("statement-not-object", "the envelope payload is not a JSON object")
                return None
        return value

    # --------------------------------------------------------------- phase 2
    def _verify_statement(self, st: dict, rep: Report) -> None:
        if st.get("_type") != STATEMENT_TYPE:
            rep.fail("statement-type-mismatch", "_type is not %s" % STATEMENT_TYPE)
        if st.get("predicateType") != PREDICATE_TYPE:
            rep.fail("predicate-type-mismatch", "predicateType is not %s (retired or foreign versions are rejected, no alias)" % PREDICATE_TYPE)
        subject = st.get("subject")
        subject_digest = None
        if not isinstance(subject, list) or len(subject) != 1:
            rep.fail("subject-count", "subject must contain exactly one entry")
        else:
            s0 = subject[0]
            d = s0.get("digest") if isinstance(s0, dict) else None
            v = d.get("sha256") if isinstance(d, dict) else None
            if is_hex64(v):
                subject_digest = v
            else:
                rep.fail("subject-digest-malformed", "subject[0].digest.sha256 must be lowercase 64-hex")
        pred = st.get("predicate")
        if not isinstance(pred, dict):
            rep.fail("predicate-missing", "predicate must be an object")
            return
        # a wrong shell does not stop the walk: the predicate is still checked so
        # the report names every independent defect.
        self._verify_predicate(pred, subject_digest, rep)

    # --------------------------------------------------------------- phase 3
    def _verify_predicate(self, pred: dict, subject_digest: Optional[str], rep: Report) -> None:
        for old in RETIRED_SPELLINGS:
            if old in pred:
                rep.fail("retired-spelling", "member %r is a retired spelling with no alias" % old)
        carried_result = pred.get("result")
        if carried_result not in RESULTS:
            rep.fail("result-out-of-vocabulary", "result must be one of %s" % ", ".join(RESULTS))
        issued_at = timestamp.parse_profile(pred.get("issuedAt"))
        if issued_at is None:
            rep.fail("issued-at-malformed", "issuedAt is absent or outside the RFC 3339 UTC profile (uppercase T, zone Z/+00:00/-00:00)")
        dna = pred.get("doesNotAssert")
        if dna is not None and not (isinstance(dna, list) and all(isinstance(x, str) for x in dna)):
            rep.fail("does-not-assert-malformed", "doesNotAssert, when present, must be an array of strings")

        env = pred.get("observationEnvironment")
        cov = pred.get("coverage")
        rows = pred.get("attackResults")
        records_raw = pred.get("observationRecords")
        structural_ok = True
        if not isinstance(env, dict):
            rep.fail("observation-environment-malformed", "observationEnvironment must be an object")
            structural_ok = False
        if not isinstance(cov, dict):
            rep.fail("coverage-malformed", "coverage must be an object")
            structural_ok = False
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            rep.fail("attack-results-malformed", "attackResults must be an array of objects")
            structural_ok = False
        if records_raw is not None and not (isinstance(records_raw, list) and all(isinstance(r, dict) for r in records_raw)):
            rep.fail("observation-records-malformed", "observationRecords, when present, must be an array of objects")
            structural_ok = False
        if not structural_ok:
            return

        env_info = self._verify_environment(env, rep)
        manifest_ids: Optional[Set[str]] = env_info["attack_ids"]
        labels, caught = env_info["labels"], env_info["caught"]

        # ---- rows --------------------------------------------------------
        n_records = len(records_raw) if isinstance(records_raw, list) else 0
        row_infos = []
        attack_ids_seen: Dict[str, int] = {}
        for i, row in enumerate(rows):
            info = self._row_info(row, labels, caught)
            row_infos.append(info)
            aid = info["attackId"]
            if not isinstance(aid, str):
                rep.fail("row-attack-id-malformed", "attackResults[%d].attackId must be a string" % i)
            else:
                if aid in attack_ids_seen:
                    rep.fail("duplicate-attack-id", "attackId %r appears on rows %d and %d" % (aid, attack_ids_seen[aid], i))
                attack_ids_seen.setdefault(aid, i)
                if manifest_ids is not None and aid not in manifest_ids:
                    rep.fail("row-attack-id-unknown", "attackResults[%d].attackId %r is not in the manifest" % (i, aid))
            al = row.get("actualLayer")
            if not isinstance(al, str):
                rep.fail("actual-layer-missing", "attackResults[%d].actualLayer is required and must be a string" % i)
            elif info["clean"] and al != "none":
                rep.fail("actual-layer-not-none", "attackResults[%d] is a clean row (nothing acted) and MUST carry actualLayer \"none\"" % i)
            refs = row.get("observationRefs")
            if refs is not None:
                if not isinstance(refs, list) or not all(is_int(x) for x in refs):
                    rep.fail("observation-refs-malformed", "attackResults[%d].observationRefs must be an array of integers" % i)
                    info["refs"] = None
                else:
                    for x in refs:
                        if x < 0 or x >= n_records:
                            rep.fail("observation-ref-out-of-range", "attackResults[%d].observationRefs index %d is out of range for observationRecords (%d)" % (i, x, n_records))
                            info["refs"] = None
            if info["basis"] == "substrate":
                if refs is None or refs == []:
                    rep.fail("substrate-row-no-refs", "attackResults[%d] is basis: substrate and MUST carry a non-empty observationRefs" % i)
                if info["class_fail_closed"]:
                    rep.fail("substrate-row-fail-closed", "attackResults[%d] is basis: substrate with a fail-closed containmentObserved or method; it cannot satisfy the class-match requirement" % i)

        # ---- coverage partition and integrity --------------------------
        assessed_ids = self._verify_coverage(cov, env_info, rep)
        if assessed_ids is not None and all(isinstance(r["attackId"], str) for r in row_infos):
            row_ids = set(r["attackId"] for r in row_infos)
            if row_ids != assessed_ids:
                missing = sorted(assessed_ids - row_ids)
                extra = sorted(row_ids - assessed_ids)
                rep.fail("coverage-integrity-mismatch", "row attackIds must equal the manifest's attacks for the assessed classes (missing %s, extra %s)" % (missing, extra))

        # ---- result recompute -------------------------------------------
        if labels is not None and caught is not None and isinstance(cov.get("outOfScope"), dict) and isinstance(cov.get("routedElsewhere"), dict):
            recomputed = self._recompute_result(row_infos, cov)
            rep.result = recomputed
            if carried_result in RESULTS and recomputed != carried_result:
                rep.fail("result-mismatch", "carried result %r but the recompute yields %r" % (carried_result, recomputed))

        # ---- records ----------------------------------------------------
        has_substrate_row = any(r["basis"] == "substrate" for r in row_infos)
        records = self._load_records(records_raw, pred, rep)
        if records is None:
            return

        # run binding (derivable only with the digests in place)
        binding = None
        if has_substrate_row:
            re_ = env.get("runEntropy")
            re_digest = (re_.get("digest") or {}).get("sha256") if isinstance(re_, dict) and isinstance(re_.get("digest"), dict) else None
            if not isinstance(re_, dict):
                rep.fail("run-entropy-missing", "runEntropy is required when any row is basis: substrate")
            elif not is_hex64(re_digest):
                rep.fail("run-entropy-digest-malformed", "runEntropy.digest.sha256 must be lowercase 64-hex")
            inputs = {
                "catchPolicy": env_info["catch_policy_digest"],
                "corpus": env_info["corpus_digest"],
                "observationVocabulary": env_info["vocab_digest"],
                "runEntropy": re_digest if is_hex64(re_digest) else None,
                "subject": subject_digest,
                "substrate": env_info["substrate_digest"],
            }
            if all(v is not None for v in inputs.values()) and isinstance(env.get("networkPosture"), dict):
                pre = dict(inputs)
                pre["aeeBindingVersion"] = BINDING_VERSION
                pre["networkPosture"] = sha256_hex(canonicalize(env["networkPosture"]))
                binding = sha256_hex(canonicalize(pre))
            else:
                rep.fail("run-binding-not-derivable", "a basis: substrate row is carried but a run binding input is missing or malformed")
        else:
            re_ = env.get("runEntropy")
            if re_ is not None and not (isinstance(re_, dict) and is_hex64((re_.get("digest") or {}).get("sha256") if isinstance(re_.get("digest"), dict) else None)):
                rep.fail("run-entropy-digest-malformed", "runEntropy, when present, must carry a lowercase 64-hex sha256 digest")

        self._evaluate_payloads(records, env_info, issued_at, manifest_ids, rep)
        self._cross_checks(records, row_infos, env_info, binding, has_substrate_row, assessed_ids or set(), rep)

        if not rep.rejected:
            rep.tiers = self._derive_tiers(row_infos, records)

    # ------------------------------------------------------- environment
    def _verify_environment(self, env: dict, rep: Report) -> dict:
        info: dict = {
            "attack_ids": None, "classes": None, "expected": None, "labels": None, "caught": None,
            "corpus_digest": None, "catch_policy_digest": None, "substrate_digest": None,
            "vocab_digest": None, "posture_digest": None,
        }

        def descriptor_digest(name: str, code: str) -> Optional[str]:
            m = env.get(name)
            d = m.get("digest") if isinstance(m, dict) else None
            v = d.get("sha256") if isinstance(d, dict) else None
            if not isinstance(m, dict):
                rep.fail(code, "observationEnvironment.%s is required and must be an object" % name)
                return None
            if not is_hex64(v):
                rep.fail(code, "observationEnvironment.%s.digest.sha256 must be lowercase 64-hex" % name)
                return None
            return v

        info["substrate_digest"] = descriptor_digest("substrate", "substrate-digest-malformed")
        info["catch_policy_digest"] = descriptor_digest("catchPolicy", "catch-policy-digest-malformed")

        # networkPosture
        np_ = env.get("networkPosture")
        if not isinstance(np_, dict):
            rep.fail("network-posture-malformed", "observationEnvironment.networkPosture is required and must be an object")
        else:
            posture = np_.get("posture")
            if not isinstance(posture, str) or posture not in POSTURE_VOCAB:
                rep.fail("network-posture-out-of-vocabulary", "networkPosture.posture must be one of %s" % ", ".join(POSTURE_VOCAB))
            d = np_.get("digest")
            v = d.get("sha256") if isinstance(d, dict) else None
            if is_hex64(v):
                info["posture_digest"] = v
            else:
                rep.fail("network-posture-digest-malformed", "networkPosture.digest.sha256 must be lowercase 64-hex")

        # corpus + manifest
        corpus = env.get("corpus")
        if not isinstance(corpus, dict):
            rep.fail("corpus-malformed", "observationEnvironment.corpus is required and must be an object")
        else:
            d = corpus.get("digest")
            cd = d.get("sha256") if isinstance(d, dict) else None
            if not is_hex64(cd):
                rep.fail("corpus-digest-malformed", "corpus.digest.sha256 must be lowercase 64-hex")
                cd = None
            manifest = corpus.get("manifest")
            if not isinstance(manifest, dict):
                rep.fail("manifest-malformed", "corpus.manifest is required and must be an object")
            else:
                ids = self._verify_manifest(manifest, rep)
                info["attack_ids"] = ids
                # The class map feeds coverage only when it is well formed: a
                # malformed manifest is already reported, and reading its
                # arrays (a number, a non-string identifier) would crash.
                info["classes"] = manifest.get("classes") if ids is not None else None
                info["expected"] = manifest.get("expectedPayloads") if isinstance(manifest.get("expectedPayloads"), dict) else None
                if cd is not None:
                    recomputed = sha256_hex(canonicalize(manifest))
                    if recomputed != cd:
                        rep.fail("corpus-digest-mismatch", "corpus.digest.sha256 does not equal the JCS digest of the carried manifest")
                    else:
                        info["corpus_digest"] = cd

        # observationVocabulary
        voc = env.get("observationVocabulary")
        if not isinstance(voc, dict):
            rep.fail("vocabulary-malformed", "observationEnvironment.observationVocabulary is required and must be an object")
        else:
            labels, caught = voc.get("labels"), voc.get("caught")
            ok = True
            for name, arr in (("labels", labels), ("caught", caught)):
                if not sorted_unique_strings(arr):
                    rep.fail("vocabulary-malformed", "observationVocabulary.%s must be an array of strings sorted ascending by UTF-16 code unit with no duplicates" % name)
                    ok = False
                elif not all(is_bmp(x) for x in arr):
                    rep.fail("vocabulary-malformed", "observationVocabulary.%s entries must be BMP-only" % name)
                    ok = False
            if ok and not set(caught) <= set(labels):
                rep.fail("vocabulary-malformed", "observationVocabulary.caught must be a subset of labels")
                ok = False
            if ok:
                info["labels"], info["caught"] = labels, caught
            d = voc.get("digest")
            vd = d.get("sha256") if isinstance(d, dict) else None
            if ok:
                recomputed = sha256_hex(canonicalize({"caught": caught, "labels": labels}))
                if vd != recomputed:
                    rep.fail("vocabulary-digest-mismatch", "observationVocabulary.digest.sha256 does not equal the JCS digest of {\"caught\": [...], \"labels\": [...]}")
                else:
                    info["vocab_digest"] = vd
        return info

    def _verify_manifest(self, manifest: dict, rep: Report) -> Optional[Set[str]]:
        classes = manifest.get("classes")
        if not isinstance(classes, dict):
            rep.fail("manifest-malformed", "corpus.manifest.classes is required and must be an object")
            return None
        ids: Set[str] = set()
        owner: Dict[str, str] = {}
        ok = True
        for cls, arr in classes.items():
            if not isinstance(arr, list) or not all(isinstance(a, str) for a in arr):
                rep.fail("manifest-malformed", "manifest.classes[%r] must be an array of attack identifier strings" % cls)
                ok = False
                continue
            for a in arr:
                if a in owner and owner[a] != cls:
                    rep.fail("manifest-attack-in-multiple-classes", "attackId %r appears under classes %r and %r" % (a, owner[a], cls))
                    ok = False
                owner.setdefault(a, cls)
                ids.add(a)
        if not ok:
            return None
        if not ids:
            rep.fail("manifest-no-attacks", "the manifest MUST declare at least one attack identifier across all of its classes")
            return None
        exp = manifest.get("expectedPayloads")
        if exp is not None:
            if not isinstance(exp, dict):
                rep.fail("expected-payloads-malformed", "corpus.manifest.expectedPayloads must be an object")
            else:
                for k, arr in exp.items():
                    if k not in ids:
                        rep.fail("expected-payloads-malformed", "expectedPayloads key %r is not an attack identifier the manifest declares" % k)
                    if not (isinstance(arr, list) and arr and sorted_unique_strings(arr) and all(is_hex64(x) for x in arr)):
                        rep.fail("expected-payloads-malformed", "expectedPayloads[%r] must be a non-empty, sorted, duplicate-free array of lowercase 64-hex values" % k)
        return ids

    # ----------------------------------------------------------- coverage
    def _verify_coverage(self, cov: dict, env_info: dict, rep: Report) -> Optional[Set[str]]:
        assessed = cov.get("assessedClasses")
        oos = cov.get("outOfScope")
        routed = cov.get("routedElsewhere")
        ok = True
        if not isinstance(assessed, list) or not all(isinstance(x, str) for x in assessed):
            rep.fail("coverage-malformed", "coverage.assessedClasses must be an array of class code strings")
            ok = False
        for name, m in (("outOfScope", oos), ("routedElsewhere", routed)):
            if not isinstance(m, dict) or not all(isinstance(v, str) for v in m.values()):
                rep.fail("coverage-malformed", "coverage.%s must be an object mapping class code to a reason string" % name)
                ok = False
        classes = env_info["classes"]
        if not ok or classes is None:
            return None
        counts: Dict[str, int] = {}
        for c in assessed:
            counts[c] = counts.get(c, 0) + 1
        for m in (oos, routed):
            for c in m:
                counts[c] = counts.get(c, 0) + 1
        partition_ok = True
        for c in classes:
            if counts.get(c, 0) != 1:
                rep.fail("coverage-partition-violation", "manifest class %r must appear in exactly one of assessedClasses/outOfScope/routedElsewhere (found %d)" % (c, counts.get(c, 0)))
                partition_ok = False
        for c in counts:
            if c not in classes:
                rep.fail("coverage-unknown-class", "class %r in coverage is not a manifest class" % c)
                partition_ok = False
        if not partition_ok:
            return None
        ids: Set[str] = set()
        for c in assessed:
            ids.update(classes[c])
        return ids

    # --------------------------------------------------------------- rows
    @staticmethod
    def _row_info(row: dict, labels, caught) -> dict:
        label = row.get("containmentObserved")
        basis = row.get("basis")
        method = row.get("method")
        attribution = row.get("attribution")
        label_known = labels is not None and isinstance(label, str) and label in labels
        is_caught = label_known and label in caught
        is_clean = label_known and not is_caught
        fail_closed = (not label_known) or basis not in BASIS_VOCAB or method not in METHOD_VOCAB or attribution not in ATTRIBUTION_VOCAB
        # Spec, Coverage validity: a basis: substrate row whose containmentObserved,
        # basis or method is fail-closed cannot class-match and is invalid.  An
        # out-of-vocabulary attribution only forces result to fail (see SPEC_NOTES).
        class_fail_closed = (not label_known) or method not in METHOD_VOCAB
        refs = row.get("observationRefs")
        return {
            "attackId": row.get("attackId"),
            "label": label,
            "basis": basis if basis in BASIS_VOCAB else None,
            "method": method if method in METHOD_VOCAB else None,
            "attribution": attribution if attribution in ATTRIBUTION_VOCAB else None,
            "caught": is_caught,
            "clean": is_clean,
            "fail_closed": fail_closed,
            "class_fail_closed": class_fail_closed,
            "refs": refs if isinstance(refs, list) else None,
        }

    @staticmethod
    def _recompute_result(row_infos: List[dict], cov: dict) -> str:
        c1 = "fail" if any(r["caught"] or r["fail_closed"] for r in row_infos) else "pass"
        c2 = "degraded" if (cov["outOfScope"] or cov["routedElsewhere"]) else "pass"
        c3 = "pass_indirect" if any(
            r["clean"] and (r["basis"] != "substrate" or r["method"] != "intercepted") for r in row_infos
        ) else "pass"
        return min((c1, c2, c3), key=RESULTS.index)

    # ------------------------------------------------------------ records
    def _load_records(self, records_raw, pred: dict, rep: Report) -> Optional[List[Record]]:
        records: List[Record] = []
        if records_raw is None:
            records_raw = []
        ok = True
        for i, env in enumerate(records_raw):
            rec = Record(i)
            pt = env.get("payloadType")
            payload = decode_base64(env.get("payload"))
            sigs = env.get("signatures")
            if not isinstance(pt, str):
                rep.fail("observation-records-malformed", "observationRecords[%d].payloadType must be a string" % i)
                ok = False
            if payload is None:
                rep.fail("observation-records-malformed", "observationRecords[%d].payload must be base64" % i)
                ok = False
            if not (isinstance(sigs, list) and sigs and all(isinstance(s, dict) and isinstance(s.get("sig"), str) for s in sigs)):
                rep.fail("observation-records-malformed", "observationRecords[%d].signatures must carry at least one entry with a string sig" % i)
                ok = False
            if ok:
                rec.payload_type = pt
                rec.payload_bytes = payload
                rec.signatures = sigs
                rec.pae = pae(pt, payload)
                rec.leaf = hashlib.sha256(b"\x00" + rec.pae).digest()
            records.append(rec)
        if not ok:
            return None
        seen: Dict[bytes, int] = {}
        for rec in records:
            if rec.leaf in seen:
                rep.fail("duplicate-record", "observationRecords[%d] and [%d] are byte-identical (same leaf hash)" % (seen[rec.leaf], rec.index))
            seen.setdefault(rec.leaf, rec.index)
        root = pred.get("batchRoot")
        if records:
            recomputed = merkle_root([r.leaf for r in records])
            if "batchRoot" not in pred:
                rep.fail("batch-root-missing", "batchRoot is required when observationRecords is non-empty")
            elif root != recomputed:
                rep.fail("batch-root-mismatch", "batchRoot does not recompute over the carried observationRecords")
        elif "batchRoot" in pred:
            rep.fail("batch-root-unexpected", "batchRoot is carried but observationRecords is absent or empty, so no root recomputes")
        return records

    def _evaluate_payloads(self, records: List[Record], env_info: dict, issued_at, manifest_ids, rep: Report) -> None:
        # observed-set recompute needs every record's kind first
        for rec in records:
            self._parse_payload(rec)
        observed_leaves = sorted(
            {r.leaf.hex() for r in records if r.kind in ("interception", "examination")}
        )
        observed_set = sha256_hex(canonicalize(observed_leaves))
        for rec in records:
            # Kind constraints are evaluated on every parsed covering-kind
            # record, including one whose aeeMethod is missing or unregistered:
            # aeeMethod is itself a constraint of three of the four kinds.
            if rec.parsed is not None and rec.parse_problem is None and rec.covering_kind:
                self._check_kind(rec, env_info, issued_at, manifest_ids, observed_set)

    def _parse_payload(self, rec: Record) -> None:
        pt = rec.payload_type or ""
        if not pt.lower().endswith("+json"):
            rec.parse_problem = "payloadType does not end in +json"
        try:
            parsed = loads_strict(rec.payload_bytes)
        except StrictJSONError as exc:
            rec.parse_problem = rec.parse_problem or ("payload is not strict I-JSON: %s" % exc)
            return
        if not isinstance(parsed, dict):
            rec.parse_problem = rec.parse_problem or "payload is not a JSON object"
            return
        rec.parsed = parsed
        if canonicalize(parsed) != rec.payload_bytes:
            rec.parse_problem = rec.parse_problem or "payload bytes are not RFC 8785 canonical"
        if not self._names_bmp(parsed):
            rec.parse_problem = rec.parse_problem or "payload carries a supplementary-plane member name"
        kind = parsed.get("aeeKind")
        binding = parsed.get("aeeRunBinding")
        method = parsed.get("aeeMethod")
        rec.kind = kind if isinstance(kind, str) else None
        rec.binding = binding if isinstance(binding, str) else None
        rec.method = method if method in METHOD_VOCAB else None
        rec.reserved_ok = rec.kind is not None and rec.binding is not None and rec.method is not None
        rec.unrecognised_reserved = sorted(k for k in parsed if k.startswith("aee") and k not in KNOWN_RESERVED)

    @staticmethod
    def _names_bmp(value) -> bool:
        if isinstance(value, dict):
            return all(is_bmp(k) and Verifier._names_bmp(v) for k, v in value.items())
        if isinstance(value, list):
            return all(Verifier._names_bmp(v) for v in value)
        return True

    def _check_kind(self, rec: Record, env_info: dict, issued_at, manifest_ids, observed_set: str) -> None:
        p = rec.parsed
        kind = rec.kind
        problems = rec.kind_problems
        posture_digest = env_info["posture_digest"]

        def id_array(name: str) -> None:
            arr = p.get(name)
            if not sorted_unique_strings(arr):
                problems.append("%s must be a duplicate-free array of strings sorted by UTF-16 code unit" % name)
            elif manifest_ids is None or not set(arr) <= manifest_ids:
                problems.append("%s names an attack identifier the manifest does not declare" % name)

        if kind == "interception":
            if rec.method is None:
                # the only kind whose aeeMethod is free still has to carry one of
                # the two registered values (L1341-L1342); without this line a
                # bound interception cited only by an artifact caught row would
                # pass the universal check with no aeeMethod at all.
                problems.append("aeeMethod must be intercepted or reconstructed")
            pc = p.get("aeePayloadCommitment")
            if not (isinstance(pc, list) and pc and sorted_unique_strings(pc) and all(is_hex64(x) for x in pc)):
                problems.append("aeePayloadCommitment must be a non-empty, sorted, duplicate-free array of lowercase 64-hex values")
        elif kind == "arming":
            if rec.method != "intercepted":
                problems.append("an arming record's aeeMethod MUST be intercepted")
            armed = timestamp.parse_profile(p.get("armedAt"))
            if armed is None:
                problems.append("armedAt is missing or outside the timestamp profile")
            elif issued_at is not None and not timestamp.not_later_than(armed, issued_at):
                problems.append("armedAt is later than issuedAt")
            if posture_digest is None or p.get("aeePostureDigest") != posture_digest:
                problems.append("aeePostureDigest must equal the pinned networkPosture digest")
            id_array("aeeAssessedAttacks")
            bv = p.get("aeeBindingVersion")
            if "aeeBindingVersion" in p and bv != BINDING_VERSION:
                rec.binding_version_problem = True
            # optional run-sequence members
            seq_present = "aeeRunSeq" in p
            prev_present = "aeePrevRunBinding" in p
            scope_present = "aeeChainScope" in p
            if seq_present:
                seq = p.get("aeeRunSeq")
                if not is_int(seq) or seq < 1:
                    problems.append("aeeRunSeq must be a positive safe-range integer")
                else:
                    if seq == 1 and prev_present:
                        problems.append("aeePrevRunBinding must be absent when aeeRunSeq is 1")
                    if seq > 1 and not prev_present:
                        problems.append("aeePrevRunBinding is required when aeeRunSeq exceeds 1")
                if prev_present and not is_hex64(p.get("aeePrevRunBinding")):
                    problems.append("aeePrevRunBinding must be a lowercase 64-hex run binding digest")
                scope = p.get("aeeChainScope")
                if not scope_present:
                    problems.append("aeeChainScope is required whenever aeeRunSeq is present")
                elif not sorted_unique_strings(scope) or not set(scope) <= set(CHAIN_SCOPE_VOCAB):
                    problems.append("aeeChainScope must be a sorted, duplicate-free array of registered dimension tokens")
            elif prev_present or scope_present:
                problems.append("aeePrevRunBinding/aeeChainScope are present without aeeRunSeq")
        elif kind == "sealed":
            if rec.method != "intercepted":
                problems.append("a sealed record's aeeMethod MUST be intercepted")
            still = p.get("aeeStillArmed")
            if not isinstance(still, bool):
                problems.append("aeeStillArmed must be a boolean")
            elif still is not True:
                problems.append("aeeStillArmed is false: the seal reports its vantage down")
            dc = p.get("aeeDropCount")
            if not is_int(dc):
                problems.append("aeeDropCount must be an integer")
            else:
                bound = p.get("aeeDropBound")
                if "aeeDropBound" in p and not is_int(bound):
                    problems.append("aeeDropBound, when present, must be an integer")
                elif dc != 0 and not (is_int(bound) and dc <= bound):
                    problems.append("aeeDropCount is non-zero and not within a declared aeeDropBound")
            if posture_digest is None or p.get("aeePostureDigest") != posture_digest:
                problems.append("aeePostureDigest must equal the pinned networkPosture digest")
            os_ = p.get("aeeObservedSet")
            if not isinstance(os_, str):
                problems.append("aeeObservedSet must be a string")
            elif os_ != observed_set:
                problems.append("aeeObservedSet does not equal the recompute over the carried interception and examination records")
                rec.observed_set_mismatch = True
            id_array("aeeObservedAttacks")
        elif kind == "examination":
            if rec.method != "reconstructed":
                problems.append("an examination record's aeeMethod MUST be reconstructed")

    # ------------------------------------------------------- cross checks
    def _cross_checks(self, records: List[Record], row_infos: List[dict], env_info: dict,
                      binding: Optional[str], has_substrate_row: bool, assessed_ids: Set[str], rep: Report) -> None:
        def resolved(info: dict) -> List[Record]:
            refs = info["refs"]
            if refs is None:
                return []
            return [records[i] for i in refs if is_int(i) and 0 <= i < len(records)]

        # every carried sealed record's aeeObservedSet must equal the recompute
        for rec in records:
            if rec.parsed is not None and rec.parse_problem is None and rec.kind == "sealed" and rec.observed_set_mismatch:
                rep.fail("observed-set-mismatch", "observationRecords[%d] (sealed) commits to a record set the statement does not carry" % rec.index)

        # a clean row resolves no index to an interception record
        for i, info in enumerate(row_infos):
            if info["clean"]:
                for rec in resolved(info):
                    if rec.kind == "interception":
                        rep.fail("clean-row-references-interception", "attackResults[%d] states nothing was caught yet resolves interception record %d" % (i, rec.index))

        # every interception record is resolved by at least one caught row
        resolved_by_caught: Set[int] = set()
        for info in row_infos:
            if info["caught"]:
                resolved_by_caught.update(r.index for r in resolved(info))
        for rec in records:
            if rec.kind == "interception" and rec.index not in resolved_by_caught:
                rep.fail("interception-unresolved", "observationRecords[%d] is an interception no caught row accounts for" % rec.index)

        # attribution: pinned
        expected = env_info["expected"] or {}
        for i, info in enumerate(row_infos):
            if info["attribution"] == "pinned":
                inter = [r for r in resolved(info) if r.kind == "interception"]
                aid = info["attackId"]
                entry = expected.get(aid) if isinstance(aid, str) else None
                if not inter:
                    rep.fail("pinned-attribution-unsupported", "attackResults[%d] declares attribution: pinned but resolves no interception record" % i)
                if not isinstance(entry, list):
                    rep.fail("pinned-attribution-unsupported", "attackResults[%d] declares attribution: pinned but corpus.manifest.expectedPayloads carries no entry for %r (such a row MUST declare paired)" % (i, aid))
                else:
                    for rec in inter:
                        pc = rec.parsed.get("aeePayloadCommitment") if rec.parsed else None
                        declared = set(x for x in entry if isinstance(x, str))  # a malformed entry is reported elsewhere
                        if not (isinstance(pc, list) and set(x for x in pc if isinstance(x, str)) & declared):
                            rep.fail("pinned-attribution-unsupported", "attackResults[%d] is pinned but interception record %d carries no commitment value the corpus declared for %r" % (i, rec.index, aid))

        if not has_substrate_row:
            return
        if binding is None:
            return  # already reported: run-binding-not-derivable

        bound = [r for r in records if r.usable and r.binding == binding]

        # every bound covering-kind record satisfies every constraint of its kind.
        # "Binds to this run" reads aeeRunBinding only (L595-L598): a record
        # whose aeeMethod is missing or unregistered still binds, and then
        # violates the aeeMethod constraint of its kind.
        for rec in [r for r in records if r.parsed is not None and r.parse_problem is None and r.binding == binding]:
            if rec.covering_kind and not rec.kind_valid:
                if rec.binding_version_problem:
                    rep.fail("binding-version-unsupported", "observationRecords[%d] declares an aeeBindingVersion this verifier does not implement" % rec.index)
                if rec.unrecognised_reserved:
                    rep.fail("%s-record-invalid" % rec.kind, "observationRecords[%d] carries unrecognised reserved member(s) %s" % (rec.index, rec.unrecognised_reserved))
                for msg in rec.kind_problems:
                    rep.fail("%s-record-invalid" % rec.kind, "observationRecords[%d]: %s" % (rec.index, msg))

        # at least one sealed record satisfying every constraint and bound to this run
        valid_seals = [r for r in bound if r.kind == "sealed" and r.kind_valid]
        if not valid_seals:
            rep.fail("sealed-record-missing", "a statement carrying a basis: substrate row MUST carry a sealed record that satisfies every constraint of its kind and binds to this run")
            rep.primary = "sealed-record-missing"

        # aeeAssessedAttacks: assessed union must be a subset (checked on every bound valid arming record)
        for rec in bound:
            if rec.kind == "arming" and rec.kind_valid:
                declared = set(rec.parsed.get("aeeAssessedAttacks") or [])
                if not assessed_ids <= declared:
                    rep.fail("assessed-attacks-not-declared", "coverage.assessedClasses covers attacks %s that arming record %d did not declare in aeeAssessedAttacks" % (sorted(assessed_ids - declared), rec.index))

        # aeeObservedAttacks: every named attack has a caught row
        caught_ids = set(info["attackId"] for info in row_infos if info["caught"] and isinstance(info["attackId"], str))
        for rec in bound:
            if rec.kind == "sealed":
                arr = rec.parsed.get("aeeObservedAttacks")
                if isinstance(arr, list):
                    for a in arr:
                        if isinstance(a, str) and a not in caught_ids:
                            rep.fail("observed-attack-without-caught-row", "sealed record %d names attack %r but no caught row carries that attackId" % (rec.index, a))

        # per substrate row
        for i, info in enumerate(row_infos):
            if info["basis"] != "substrate" or info["class_fail_closed"]:
                continue
            recs = resolved(info)
            if not recs:
                continue  # substrate-row-no-refs / out-of-range already reported
            row_ok = True
            for rec in recs:
                if not rec.usable:
                    rep.fail("referenced-record-unparseable", "attackResults[%d] references record %d whose payload is not a canonical +json object carrying the reserved members (%s)" % (i, rec.index, rec.parse_problem or "reserved members missing or malformed"))
                    row_ok = False
                elif rec.binding != binding:
                    rep.fail("run-binding-mismatch", "attackResults[%d] references record %d whose aeeRunBinding does not equal the derived run binding" % (i, rec.index))
                    row_ok = False
                elif rec.binding_version_problem:
                    row_ok = False  # reported above as binding-version-unsupported
            if not row_ok:
                continue
            kinds_valid = [r for r in recs if r.kind_valid]
            non_covering = [r for r in recs if r.kind in NON_COVERING_REGISTERED]
            unknown = [r for r in recs if r.kind not in COVERING_KINDS and r.kind not in NON_COVERING_REGISTERED]
            if info["method"] == "reconstructed":
                need = any(r.kind == "examination" for r in kinds_valid)
                what = "at least one examination record"
            elif info["caught"]:
                need = any(r.kind == "interception" for r in kinds_valid)
                what = "at least one interception record"
            else:
                armings = [r for r in kinds_valid if r.kind == "arming"]
                seals = [r for r in kinds_valid if r.kind == "sealed"
                         and all(r.parsed.get("aeePostureDigest") == a.parsed.get("aeePostureDigest") for a in armings)]
                need = bool(armings) and bool(seals)
                what = "at least one arming record and at least one covering sealed record"
            if not need:
                rep.fail("class-match-failed", "attackResults[%d] (%s, %s) must reference %s" % (i, "caught" if info["caught"] else "clean", info["method"], what))
                if non_covering and not kinds_valid:
                    rep.fail("row-resolves-non-covering-kind", "attackResults[%d] resolves only records of registered kinds that cover nothing (%s)" % (i, sorted(set(r.kind for r in non_covering))))
                elif unknown and not kinds_valid:
                    rep.fail("row-resolves-unrecognised-kind", "attackResults[%d] resolves only records of kinds this verifier does not recognise" % i)
            # method cap: no stronger than the weakest aeeMethod across covering records
            covering = [r for r in recs if r.covering_kind]
            if info["method"] == "intercepted" and any(r.method == "reconstructed" for r in covering):
                rep.fail("method-cap-violation", "attackResults[%d] declares method: intercepted but a covering record was signed aeeMethod: reconstructed" % i)

    # -------------------------------------------------------------- tiers
    def _derive_tiers(self, row_infos: List[dict], records: List[Record]) -> List[str]:
        verified_cache: Dict[int, bool] = {}

        def record_verifies(rec: Record) -> bool:
            if rec.index in verified_cache:
                return verified_cache[rec.index]
            ok = False
            if self.keys:
                for sig in rec.signatures:
                    raw = decode_base64(sig.get("sig"))
                    if raw is None:
                        continue
                    hint = sig.get("keyid")
                    ordered = sorted(self.keys, key=lambda k: 0 if k[0] == hint else 1)
                    if any(ed25519.verify(pk, rec.pae, raw) for _, pk in ordered):
                        ok = True
                        break
            verified_cache[rec.index] = ok
            return ok

        tiers = []
        for info in row_infos:
            if info["basis"] != "substrate":
                tiers.append("declared")
                continue
            refs = info["refs"] or []
            covering = [records[i] for i in refs if records[i].covering_kind]
            attested = bool(self.keys) and bool(covering) and all(record_verifies(r) for r in covering)
            tiers.append("attested" if attested else "unattested")
        return tiers
