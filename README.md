# aee-verifier

A verifier for the in-toto predicate **Adversarial Execution Evidence**
(predicate type `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`,
version 0.7.0), built from the specification text at agent-evidence-vectors
v0.12.1 and the material listed under "Sources used", for the Empirical Software Engineering study
"do independent builds of one spec share mistakes?" (finos/ai-governance-framework#337,
`docs/study/emse-2026/builders.md`).

It reads one statement and decides whether it is valid: for a valid statement
it prints the recomputed `result` and the per-row evidence tiers; for an
invalid one it prints the conditions it violated.

## Run

```
/path/to/aee-verifier/aee-verify <statement.json>      # from any directory
# or, from the repository root only
python3 -m aee_verifier <statement.json>
```

`python3 -m aee_verifier` finds the package only when the current directory is
the repository root (elsewhere Python exits 1 with "No module named
aee_verifier" and prints no JSON line); the `aee-verify` launcher adds its own
directory to the path and works from anywhere.

Python 3.9 or later, standard library only (no third-party dependency; the
Ed25519 verifier is RFC 8032 in plain Python).  Tested on CPython 3.9.25,
3.11.2 and 3.13.15.

Consumer key policy (optional) via the environment variable the harness
documents: `AEE_SUBSTRATE_KEYS=/path/to/keys.json` holding
`{"substrateObservationKeys": [{"keyid": "...", "publicKeyHex": "<64 hex>"}]}`
(32-byte raw Ed25519 public keys).  Unset: every `basis: substrate` row
derives `unattested`.

### Output

Human-readable lines, then **one JSON object on the last line**:

```
{"verdict":"accept","codes":[],"result":"pass","tiers":["attested","attested","attested"]}
{"verdict":"reject","codes":["result-mismatch"],"result":null,"tiers":[],"primaryCode":"result-mismatch"}
```

* `verdict`: `accept` or `reject` (`error`, with code `usage` or
  `unreadable-input`, on exit status 2).
* `codes`: the conditions found (this verifier's own names, below); empty on accept.
* `result`: the recomputed token (`fail` < `degraded` < `pass_indirect` < `pass`), `null` on reject.
* `tiers`: one of `declared` / `attested` / `unattested` per `attackResults` row, in order; `[]` on reject.
* `primaryCode` (optional in the harness contract): the first condition found,
  except that an unmet sealed-record existence requirement is always primary
  (spec, "Coverage validity").

Exit status: `0` accept, `1` reject, `2` the verifier could not run
(unreadable input or bad invocation).

The input file may be the bare in-toto Statement or a DSSE envelope
(`application/vnd.in-toto+json`) wrapping it; the envelope signature is not
verified (the harness defines no envelope key channel).

## What it covers

Stage one (byte-pure, every statement):

* strict I-JSON on the raw bytes: UTF-8 without overlong forms or CESU-8,
  duplicate members at any depth, `\u` escapes of exactly four hex digits,
  surrogate pairing, noncharacters, raw control characters, nesting depth
  ≤ 128, integers below 2^53 — with its own parser (the standard `json`
  module accepts several of these);
* Statement shell (`_type`, exactly one `subject` with lowercase 64-hex
  `sha256`, `predicateType` v0.7), predicate members and types, retired
  spellings, `issuedAt` profile;
* `observationEnvironment`: descriptor digests, closed posture vocabulary,
  manifest rules (classes, one class per attack, at least one attack,
  `expectedPayloads`), JCS recompute of `corpus.digest` and of the
  vocabulary digest, vocabulary ordering (UTF-16 code unit), BMP-only;
* `coverage` partition and attack-granularity coverage integrity;
* `attackResults`: manifest membership, uniqueness, `actualLayer`,
  `observationRefs` typing and range, fail-closed vocabularies;
* the `result` recompute (minimum of three conditions) against the carried value;
* `observationRecords`: envelope structure, RFC 6962 `batchRoot` with
  domain separation, byte-identical records, strict canonical `+json`
  payloads (RFC 8785 re-serialisation compared byte for byte), reserved
  members, every kind constraint (interception, arming incl. the optional
  run-sequence members, sealed incl. `aeeObservedSet` / `aeeObservedAttacks`,
  examination), unrecognised `aee*` members, `aeeBindingVersion`;
* run binding version 2 derivation and comparison on every referenced record;
* the whole coverage validity list: per substrate row (refs, class match,
  canonical payloads, binding, method cap) and statement-wide (clean rows
  never cite an interception, every interception is accounted for, a valid
  sealed record exists, every bound covering record is valid, observed set,
  `pinned` attribution against `expectedPayloads`, `aeeAssessedAttacks`
  subset, `aeeObservedAttacks` obligation).

Stage two (trust-relative): the per-row evidence tier from DSSE PAE Ed25519
signature verification against the pinned keys.

## What it does not cover

* Consumer policy obligations: corpus / substrate anchor pins, demanded
  classes, requiring `pinned` or a non-empty `aeeObservedAttacks`, key
  validity windows, `runEntropy` reuse across statements, cross-run chain
  rules.  The spec places these outside validity and the harness offers no
  channel for them.
* The enclosing envelope signature (no key channel).
* Producer obligations the spec itself says no verifier can check (canonical
  commitment forms in the corpus, drop-count honesty, seal timing, shared
  reference evidencing on `paired` rows).
* Signature algorithms other than Ed25519.

Condition names are this verifier's own (the specification defines none and
the suite's registry was not consulted); the 75 distinct condition codes it
can emit are the 62 listed by `grep -o 'rep.fail("[a-z0-9-]*"'
aee_verifier/verifier.py | sort -u`, the two passed through a helper
(`substrate-digest-malformed`, `catch-policy-digest-malformed`), the parser
codes (`invalid-utf8`, `duplicate-member`, `nesting-depth-exceeded`,
`ill-formed-string`, `integer-out-of-safe-range`, `number-out-of-range`,
`malformed-json`) and the four `<kind>-record-invalid` names.

## Sources used

Only the material the study permits:

* `spec/adversarial-execution-evidence-v0.12.1.md` — the pinned spec,
  sha256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0` (verified);
* `spec/pypi-0.12.1-README-what-the-suite-compares.md` — the output contract
  section of the agent-evidence-vectors 0.12.1 README on PyPI;
* `builders.md` (study rules);
* public standards the spec cites, downloaded from their primary sources:
  in-toto attestation framework (Statement v1, ResourceDescriptor, DigestSet,
  parsing rules), DSSE envelope and protocol, RFC 8785 (JCS, incl. Appendix B
  samples), RFC 7493, RFC 3339, RFC 6962, RFC 8032 (Ed25519 and its test
  vectors);
* RFC 8259 (section 8.1, byte order mark) and RFC 6838 (section 4.2, case of
  media type names) are cited in SPEC_NOTES from prior knowledge; they were not
  downloaded or re-read for this build.

Not opened: the test set, its changelog, the reference `aee` / `aee-verify`
rails, `aee/codes.go`, any other verifier for this predicate, any other file
of the agent-evidence-vectors repository.  Every place where the text alone
did not decide a behaviour is recorded in `SPEC_NOTES.md`; the
requirement-by-requirement inventory is in `REQUIREMENTS.md`.

## Tests

```
python3 -m unittest discover -s tests -p "test_*.py"     # 210 tests
python3 tests/mutate.py --module verifier               # mutation testing (positive control)
```

* `tests/test_verifier.py` (163 tests): one or more accept/reject cases per
  requirement, generated by `tests/builder.py`, a test-only producer that
  signs internally consistent statements so each test perturbs one thing.
* `tests/test_units.py` (26 tests): JCS against RFC 8785 Appendix B and the
  section 3.2.3 sort vector, the strict parser against 66 negative and 23
  positive documents, RFC 3339 calendar rules, RFC 8032 vectors and
  malformed signatures / point encodings (with `cryptography` as an optional
  independent oracle when installed), key-policy loading.
* `tests/test_review_fixes.py` (21 tests): the defects found by the review
  before posting (below), each test failing on the first build or killing a
  mutant the first build's suite let survive.
* Mutation testing (`tests/mutate.py`, measured 2026-10-08 on CPython 3.11.2
  after the review fixes): 861 mutants, 817 killed, 44 survived; every
  survivor is classified in `tests/MUTATION.md` (equivalent or
  verdict-equivalent: message text, short-circuit flags, key-ordering,
  constants whose change is masked by a later step).

## Review before posting

An independent review of the first build (`fea61aa`) found, and these commits
correct:

* three inputs that crashed the verifier (an integer token of more than 4300
  digits, a manifest class that is not an array of strings, an
  `expectedPayloads` entry holding a non-string) and a reject reason that
  could not be printed under a non-UTF-8 stdout; each ended with exit status 1
  and no JSON line;
* `$` and `\d` in the hex and timestamp patterns: a lowercase-64-hex value
  followed by a newline, and timestamps with a trailing newline or non-ASCII
  digits, were accepted;
* the universal kind check skipped a run-bound `arming` / `sealed` /
  `examination` record whose `aeeMethod` was missing or unregistered
  (SPEC_NOTES N31);
* three mutation survivors classified as equivalent that were not, and
  documentation counts (condition codes, sources).


## Tools and model

Written with Claude Code, model Claude Fable 5.1 (`claude-fable-5-1`), as the
agent "Noûs" working for Roberto Locatelli, who directed the work and is
responsible for it; a separate Claude Opus 5.5 instance reviews the build
before it is posted.  Neither agent opened the test set, its changelog or
another implementation while building or reviewing (checked against the
builder's session transcript).  Earlier, separate sessions in the same
environment had listed the file names at the top of `vectors/` and read the
first 48 lines of `vectors/indeterminate/INDEX.md`, and had cloned or
installed agent-evidence-vectors 0.13.0 to run another family; no statement of
this predicate's test set and no changelog were opened.  That exposure is
declared in our reply on finos/ai-governance-framework#337.

## License

Apache License 2.0 — see `LICENSE`.

Copyright 2026 Roberto Locatelli.
