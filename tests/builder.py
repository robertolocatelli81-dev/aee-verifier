"""Test-only producer: builds complete, internally consistent AEE 0.7 statements
from a small configuration, following the spec text.  It is NOT a reference
implementation; it exists so each test can perturb one thing and know what
the verifier must say.

The builder deliberately re-implements the derivations (run binding,
observed set, batch root) in plain code here rather than importing them from
the verifier, so that a bug shared by both would have to be made twice.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from aee_verifier import ed25519  # noqa: E402
from aee_verifier.jcs import canonicalize  # noqa: E402

PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# deterministic keys for the fixtures
SUBSTRATE_SEED = bytes(range(32))
SUBSTRATE_KEYID = "substrate-2026"
SUBSTRATE_PUB = ed25519.public_key_from_seed(SUBSTRATE_SEED)
OTHER_SEED = bytes(range(1, 33))
OTHER_PUB = ed25519.public_key_from_seed(OTHER_SEED)


def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def merkle_root(leaves):
    if not leaves:
        return None

    def node(xs):
        if len(xs) == 1:
            return xs[0]
        k = 1
        while k * 2 < len(xs):
            k *= 2
        return hashlib.sha256(b"\x01" + node(xs[:k]) + node(xs[k:])).digest()

    return node(leaves).hex()


COMMIT_1 = h("commitment:CO-EXFIL-1")
COMMIT_2 = h("commitment:CO-EXFIL-2")
COMMIT_FS = h("commitment:FS-WRITE-1")

DEFAULT = {
    "classes": {"CO": ["CO-EXFIL-1", "CO-EXFIL-2"], "FS": ["FS-WRITE-1"]},
    "expectedPayloads": {"CO-EXFIL-1": [COMMIT_1], "FS-WRITE-1": [COMMIT_FS]},
    "labels": ["egress_captured", "file_written", "no_egress", "no_write"],
    "caught": ["egress_captured", "file_written"],
    "posture": "sinkhole",
    "postureDigest": h("posture-config"),
    "substrateDigest": h("substrate-image"),
    "catchPolicyDigest": h("catch-policy"),
    "subjectDigest": h("artifact"),
    "runEntropyDigest": h("run-entropy"),
    "issuedAt": "2026-06-23T16:08:07Z",
    "armedAt": "2026-06-23T16:00:00Z",
    "assessedClasses": ["CO", "FS"],
    "outOfScope": {},
    "routedElsewhere": {},
    # records: name -> spec; order in the array is this list's order
    "records": [
        {"name": "int1", "kind": "interception", "commitment": [COMMIT_1], "method": "intercepted"},
        {"name": "arm", "kind": "arming"},
        {"name": "exam", "kind": "examination"},
        {"name": "seal", "kind": "sealed"},
    ],
    "rows": [
        {"attackId": "CO-EXFIL-1", "containmentObserved": "egress_captured", "basis": "substrate",
         "method": "intercepted", "attribution": "pinned", "actualLayer": "policy.egress_sinkhole", "refs": ["int1"]},
        {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "substrate",
         "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
        {"attackId": "FS-WRITE-1", "containmentObserved": "no_write", "basis": "substrate",
         "method": "reconstructed", "attribution": "paired", "actualLayer": "none", "refs": ["exam"]},
    ],
    "observedAttacks": ["CO-EXFIL-1"],
    "sealExtra": {},
    "armExtra": {},
    "result": None,  # None = recompute
    "doesNotAssert": ["behaviour outside the thrown corpus"],
    "signerSeed": SUBSTRATE_SEED,
    "keyid": SUBSTRATE_KEYID,
    "payloadType": "application/vnd.example.aee-observation+json",
}


def recompute_result(cfg):
    labels, caught = cfg["labels"], cfg["caught"]
    rows = cfg["rows"]
    c1 = "fail" if any((r["containmentObserved"] in caught) or (r["containmentObserved"] not in labels)
                       or r["basis"] not in ("substrate", "artifact") or r["method"] not in ("intercepted", "reconstructed")
                       or r["attribution"] not in ("pinned", "paired") for r in rows) else "pass"
    c2 = "degraded" if (cfg["outOfScope"] or cfg["routedElsewhere"]) else "pass"
    c3 = "pass_indirect" if any(r["containmentObserved"] in labels and r["containmentObserved"] not in caught
                                and (r["basis"] != "substrate" or r["method"] != "intercepted") for r in rows) else "pass"
    order = ["fail", "degraded", "pass_indirect", "pass"]
    return min((c1, c2, c3), key=order.index)


def build(overrides=None, **kw):
    """Return (statement_dict, info) where info has the binding and per-record payloads."""
    cfg = copy.deepcopy(DEFAULT)
    if overrides:
        cfg.update(copy.deepcopy(overrides))
    cfg.update(copy.deepcopy(kw))

    manifest = {"classes": cfg["classes"]}
    if cfg["expectedPayloads"] is not None:
        manifest["expectedPayloads"] = cfg["expectedPayloads"]
    corpus_digest = sha256_hex(canonicalize(manifest))
    vocab_digest = sha256_hex(canonicalize({"caught": cfg["caught"], "labels": cfg["labels"]}))
    network_posture = {"posture": cfg["posture"], "digest": {"sha256": cfg["postureDigest"]}}
    if cfg.get("postureExtra"):
        network_posture.update(cfg["postureExtra"])

    binding_pre = {
        "aeeBindingVersion": "2",
        "catchPolicy": cfg["catchPolicyDigest"],
        "corpus": corpus_digest,
        "networkPosture": sha256_hex(canonicalize(network_posture)),
        "observationVocabulary": vocab_digest,
        "runEntropy": cfg["runEntropyDigest"],
        "subject": cfg["subjectDigest"],
        "substrate": cfg["substrateDigest"],
    }
    binding = sha256_hex(canonicalize(binding_pre))

    all_ids = sorted(a for arr in cfg["classes"].values() for a in arr)
    has_substrate = any(r["basis"] == "substrate" for r in cfg["rows"])

    # --- records -----------------------------------------------------------
    payloads = {}
    for spec in cfg["records"]:
        p = {"aeeRunBinding": spec.get("binding", binding), "aeeKind": spec["kind"]}
        k = spec["kind"]
        if k == "interception":
            p["aeeMethod"] = spec.get("method", "intercepted")
            p["aeePayloadCommitment"] = spec.get("commitment", [COMMIT_1])
            p["destination"] = spec.get("destination", "203.0.113.7:443")
        elif k == "arming":
            p["aeeMethod"] = spec.get("method", "intercepted")
            p["armedAt"] = spec.get("armedAt", cfg["armedAt"])
            p["aeePostureDigest"] = spec.get("postureDigest", cfg["postureDigest"])
            p["aeeAssessedAttacks"] = spec.get("assessed", all_ids)
            p.update(cfg["armExtra"])
        elif k == "sealed":
            p["aeeMethod"] = spec.get("method", "intercepted")
            p["aeeStillArmed"] = spec.get("stillArmed", True)
            p["aeeDropCount"] = spec.get("dropCount", 0)
            if "dropBound" in spec:
                p["aeeDropBound"] = spec["dropBound"]
            p["aeePostureDigest"] = spec.get("postureDigest", cfg["postureDigest"])
            p["aeeObservedAttacks"] = spec.get("observedAttacks", cfg["observedAttacks"])
            p["aeeObservedSet"] = None  # filled below
            p.update(cfg["sealExtra"])
        elif k == "examination":
            p["aeeMethod"] = spec.get("method", "reconstructed")
            p["states"] = ["snap-0", "snap-1"]
        else:
            p["aeeMethod"] = spec.get("method", "intercepted")
            p["note"] = "producer vocabulary"
        p.update(spec.get("extra", {}))
        for key in spec.get("drop", []):
            p.pop(key, None)
        payloads[spec["name"]] = p

    def envelope(name, p, spec):
        raw = spec.get("rawPayload")
        body = raw if raw is not None else canonicalize(p)
        if spec.get("patchPayload"):                 # (old, new) byte replacement, for inputs canonicalize refuses
            old, new = spec["patchPayload"]
            assert body.count(old) == 1, old
            body = body.replace(old, new)
        pt = spec.get("payloadType", cfg["payloadType"])
        pae = b"DSSEv1 " + str(len(pt.encode())).encode() + b" " + pt.encode() + b" " + str(len(body)).encode() + b" " + body
        seed = spec.get("seed", cfg["signerSeed"])
        sig = ed25519.sign(seed, pae)
        env = {"payload": b64(body), "payloadType": pt,
               "signatures": [{"keyid": spec.get("keyid", cfg["keyid"]), "sig": b64(sig)}]}
        if spec.get("badSig"):
            env["signatures"][0]["sig"] = b64(bytes(64))
        return env, pae

    # first pass: leaves of interception/examination for the observed set
    pre_envs = {}
    for spec in cfg["records"]:
        if spec["kind"] in ("interception", "examination"):
            env, pae = envelope(spec["name"], payloads[spec["name"]], spec)
            pre_envs[spec["name"]] = (env, pae)
    observed_leaves = sorted(hashlib.sha256(b"\x00" + pae).digest().hex() for (_, pae) in pre_envs.values())
    observed_set = sha256_hex(canonicalize(observed_leaves))
    for spec in cfg["records"]:
        if spec["kind"] == "sealed":
            payloads[spec["name"]]["aeeObservedSet"] = spec.get("observedSet", observed_set)
        for key in spec.get("drop", []):
            payloads[spec["name"]].pop(key, None)

    records, leaves, index_of = [], [], {}
    for spec in cfg["records"]:
        if spec["name"] in pre_envs:
            env, pae = pre_envs[spec["name"]]
        else:
            env, pae = envelope(spec["name"], payloads[spec["name"]], spec)
        index_of[spec["name"]] = len(records)
        records.append(env)
        leaves.append(hashlib.sha256(b"\x00" + pae).digest())

    rows = []
    for r in cfg["rows"]:
        row = {k: v for k, v in r.items() if k != "refs"}
        if "refs" in r and r["refs"] is not None:
            row["observationRefs"] = [index_of[n] if isinstance(n, str) else n for n in r["refs"]]
        rows.append(row)

    predicate = {
        "result": cfg["result"] or recompute_result(cfg),
        "observationEnvironment": {
            "substrate": {"name": "ghcr.io/example/substrate:1.4", "digest": {"sha256": cfg["substrateDigest"]}},
            "corpus": {"name": "example-corpus", "uri": "pkg:generic/example/corpus@1.0.0",
                       "digest": {"sha256": corpus_digest}, "manifest": manifest},
            "catchPolicy": {"digest": {"sha256": cfg["catchPolicyDigest"]}},
            "networkPosture": network_posture,
            "observationVocabulary": {"digest": {"sha256": vocab_digest}, "labels": cfg["labels"], "caught": cfg["caught"]},
        },
        "coverage": {"assessedClasses": cfg["assessedClasses"], "outOfScope": cfg["outOfScope"],
                     "routedElsewhere": cfg["routedElsewhere"]},
        "attackResults": rows,
        "issuedAt": cfg["issuedAt"],
    }
    if has_substrate or cfg.get("forceRunEntropy"):
        predicate["observationEnvironment"]["runEntropy"] = {"digest": {"sha256": cfg["runEntropyDigest"]}}
    if records or cfg.get("forceRecords"):
        predicate["observationRecords"] = records
        if records:
            predicate["batchRoot"] = merkle_root(leaves)
    if cfg["doesNotAssert"] is not None:
        predicate["doesNotAssert"] = cfg["doesNotAssert"]

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "example-tool", "digest": {"sha256": cfg["subjectDigest"]}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    info = {"binding": binding, "payloads": payloads, "index": index_of, "observedSet": observed_set,
            "corpusDigest": corpus_digest, "vocabDigest": vocab_digest, "leaves": leaves}
    return statement, info


def dumps(statement) -> bytes:
    return json.dumps(statement, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------- scenarios

def scenario_fail():
    """Default: one caught pinned row, one clean intercepted row, one clean reconstructed row -> fail."""
    return build()


def scenario_pass():
    return build(
        records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
        rows=[
            {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
            {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
            {"attackId": "FS-WRITE-1", "containmentObserved": "no_write", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
        ],
        observedAttacks=[],
    )


def scenario_pass_indirect():
    st_cfg = dict(
        records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}, {"name": "exam", "kind": "examination"}],
        rows=[
            {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
            {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "artifact",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none"},
            {"attackId": "FS-WRITE-1", "containmentObserved": "no_write", "basis": "substrate",
             "method": "reconstructed", "attribution": "paired", "actualLayer": "none", "refs": ["exam"]},
        ],
        observedAttacks=[],
    )
    return build(**st_cfg)


def scenario_degraded():
    return build(
        records=[{"name": "arm", "kind": "arming"}, {"name": "seal", "kind": "sealed"}],
        assessedClasses=["CO"], outOfScope={"FS": "filesystem vantage unavailable on this substrate"},
        rows=[
            {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
            {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "substrate",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none", "refs": ["arm", "seal"]},
        ],
        observedAttacks=[],
    )


def scenario_artifact_only():
    """No substrate row: no records, no batchRoot, no runEntropy; result pass_indirect."""
    return build(
        records=[],
        rows=[
            {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "artifact",
             "method": "intercepted", "attribution": "paired", "actualLayer": "none"},
            {"attackId": "CO-EXFIL-2", "containmentObserved": "no_egress", "basis": "artifact",
             "method": "reconstructed", "attribution": "paired", "actualLayer": "none"},
            {"attackId": "FS-WRITE-1", "containmentObserved": "file_written", "basis": "artifact",
             "method": "reconstructed", "attribution": "paired", "actualLayer": "none"},
        ],
    )


def scenario_fully_skipped():
    """Honest fully-skipped run: every class disclosed, zero rows -> degraded."""
    return build(records=[], rows=[], assessedClasses=[],
                 outOfScope={"CO": "no network vantage"}, routedElsewhere={"FS": "assessed by sibling run"})


def key_policy_file(path, keys=((SUBSTRATE_KEYID, SUBSTRATE_PUB),)):
    doc = {"substrateObservationKeys": [{"keyid": k, "publicKeyHex": pk.hex()} for k, pk in keys]}
    with open(path, "w") as fh:
        json.dump(doc, fh)
    return path
