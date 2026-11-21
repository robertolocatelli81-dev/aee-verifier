# SPEC_NOTES — reading the AEE predicate text, v0.12.1 (predicate 0.7.0)

Every point where the specification text alone did not decide the verifier's
behaviour, with the section, the exact words, and the choice made.  Line
numbers (`L…`) refer to `spec/adversarial-execution-evidence-v0.12.1.md`
(sha256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`).
"README" refers to `spec/pypi-0.12.1-README-what-the-suite-compares.md`, which
holds three sections of the PyPI 0.12.1 README: "What the suite compares"
(L1–L91), "The registry" (L92–L123) and "Indeterminate vectors" (L124–L174).

Nothing outside those two files, builders.md and the public standards they
cite (in-toto Statement/ResourceDescriptor/parsing rules, DSSE
envelope/protocol, RFC 8785, RFC 7493, RFC 8259, RFC 3339, RFC 6962,
RFC 8032) was read.  The test set, its changelog, the reference `aee` /
`aee-verify` rails, `aee/codes.go`, `vectors/MANIFEST.json`,
`docs/interpretation-decisions-open.md`, `vectors/indeterminate/INDEX.md`, the
protobuf schema, and every other implementation were NOT opened.

## 1. References the text makes to material outside itself

| # | Where | Reference | What was done |
|---|-------|-----------|---------------|
| R1 | L2317 `[ResourceDescriptor]: ../v1/resource_descriptor.md` | in-toto framework file | Read from the in-toto attestation repository (public standard the spec says it builds on). Used for: `name` optional, `digest` a DigestSet with lowercase hex. |
| R2 | L2318–L2322 `[Runtime Traces]`, `[SCAI]`, `[SVR]`, `[Test Result]`, `[VSA]` | sibling predicates | Not opened; nothing normative depends on them. |
| R3 | L866 "the proto beside it already described this vocabulary as closed" | protobuf schema in the repo | Not opened. The text itself closes the vocabulary at four values (L847–L855); that is what is implemented. |
| R4 | L841 "the versioning commitment recorded in the changelog", L1778 "see the changelog" | the spec's own "Changelog and Migrations" section | Internal to the file; no external document needed. |
| R5 | README L98 "`aee/codes.go` is the enumerated set", README L94 "The codes are this suite's registry rather than the specification's" | the suite's failure-code registry | Not opened. The spec "defines no condition vocabulary" (L641, L1407). This verifier uses its own kebab-case code names (listed in README.md). Consequence for the study: the harness compares code sets against the registry, so this rail's codes will intersect the manifest only where the study maps them; verdict, `result` and `tiers` are directly comparable. |
| R6 | README L121 `docs/interpretation-decisions-open.md`, L164 `vectors/indeterminate/INDEX.md` | repository documents | Not opened (forbidden material). |
| R7 | L1680–L1682 SCITT RFC 9943 / COSE receipts RFC 9942, L193 drand, L194 RFC 9334 | external completions | Informative only; nothing implemented. |

## 2. Ambiguities, contradictions and decisions

Format: **where** — "quote" — *issue* — **choice**.

### Input and output contract

**N1. Input shape.** builders.md: "Your verifier reads one statement"; README L3: "runs an external verifier as `<cmd> <vector-file>`"; L410 names "the envelope signature" as stage two. *Is the file a bare in-toto Statement or a DSSE envelope wrapping one?* **Choice:** accept both. An object with `payload`/`payloadType`/`signatures` and no `_type` is unwrapped when `payloadType` is `application/vnd.in-toto+json`; its signature is not verified (no envelope key channel exists in the README contract). The inner bytes are parsed under the same strict profile.

**N2. Exit status.** README L4: "reads the verdict from the exit status" — the mapping is not written in the section. **Choice:** 0 accept, 1 reject, 2 the verifier could not run (unreadable input / usage).

**N3. JSON line members.** README L5–L6 gives the shape `{"verdict": ..., "codes": [...], "result": ..., "tiers": [...]}` without the token values. **Choice:** `verdict` is `"accept"` or `"reject"` (the bucket names, README L126–L127); `result` is the recomputed token on accept and `null` on reject; `tiers` is one entry per `attackResults` row in array order (`declared` / `attested` / `unattested`), `[]` on reject (the tier is defined "Given a valid attestation", L766). `primaryCode` is emitted (README L8–L13, optional) as the first condition found, overridden by the spec's one stated precedence (N38).

**N4. Code vocabulary.** See R5. The spec names conditions in prose only. The names used here are documented in README.md and never change meaning.

### Prerequisites (bytes)

**N5. Safe-integer rule, statement-wide.** L100–L102 "Producers MUST enforce the RFC 7493 (I-JSON) safe-integer profile on canonicalized content: integers with magnitude at or above 2^53 MUST be rejected"; L104 "The whole statement JSON is parsed as strict I-JSON". *The first sentence scopes the rule to canonicalized content, the second to the whole statement.* **Choice:** reject an integer token (no fraction, no exponent) of magnitude ≥ 2^53 anywhere in the statement and in every record payload. Numbers with a fraction or exponent are parsed as doubles (and rejected only if they overflow); RFC 7493 §2.2 itself only says SHOULD NOT for those.

**N6. Depth bound for payloads.** L148 "Record payloads are parsed under the same bound." **Choice:** a payload is parsed as its own document; its outermost `{` is depth 1 (the depth of the statement does not carry over). The statement's own bound counts the statement's outermost `{` as 1 (L140–L141).

**N7. Byte order mark.** L113 "the statement MUST be valid UTF-8". RFC 8259 §8.1 says implementations MUST NOT add a BOM and MAY ignore one. **Choice:** a leading BOM is not part of a JSON text and is rejected (`malformed-json`).

**N8. Where the string rules apply.** L111–L127 apply to "any statement in which a string literal is not a well-formed sequence of Unicode scalar values", "at any depth and in both member-name and value position". **Choice:** the same parser is used for the statement and every record payload; noncharacters are rejected in names and values at any depth.

### Statement shell

**N9. `_type`.** Not restated by the predicate. The in-toto Statement specification requires `_type` = `https://in-toto.io/Statement/v1`. **Choice:** required and checked (`statement-type-mismatch`).

**N10. Retired spellings.** L1974–L1976 "the old spelling is rejected", L2033–L2034 "old spellings rejected, no alias" (`does_not_assert`, `interceptRecords`, `interceptRefs`). *"Rejected" could mean "not accepted as an alias" (ignored like any unknown member under the framework's parsing rules, in-toto README "Consumers MUST ignore unrecognized fields") or "makes the statement malformed".* **Choice:** their presence makes the statement malformed (`retired-spelling`). All other unknown members are ignored; `evidenceTier` and predicate-level `aee*` members are ignored as L779–L781 requires.

**N11. `predicate` optionality.** The Statement specification makes `predicate` optional; this predicate requires several of its members. **Choice:** a missing or non-object `predicate` is malformed.

**N12. `doesNotAssert` type.** L1772 "_array of strings, optional_"; L1775 "a verifier MUST NOT require it, and nothing in it weakens the required checks". **Choice:** absent is fine; present but not an array of strings is malformed (`does-not-assert-malformed`). The MUST NOT is about requiring the member, not about ignoring a type violation.

### observationEnvironment

**N13. Scope of the digest-format rule.** L212–L218: "`catchPolicy`, `corpus`, `runEntropy`, `substrate` and `subject[0]` MUST each carry a `sha256` digest whose value is already lowercase 64-hex, and so MUST `networkPosture` …; a substrate-row-carrying statement violating this digest requirement is malformed." *Read literally, an artifact-only statement may carry a malformed substrate digest.* **Choice:** the five always-required members (`substrate`, `catchPolicy`, `corpus`, `networkPosture`, `subject[0]`) must carry lowercase 64-hex `sha256` on every statement: they are "required" (L785–L786), the DigestSet type says lowercase hex, and `corpus` is recomputed anyway. `runEntropy` is required exactly when a substrate row exists (L808–L810) and, when present on an artifact-only statement, must still be well-formed.

**N14. Unauthenticated names.** L531–L540: `corpus.name`, `corpus.uri`, `substrate.name`, `subject[0].name` — "No digest, no record payload, and no gate reads them". The schema (L315, L321–L324) shows them. **Choice:** not required, never read.

**N15. Manifest duplicates within one class.** L790–L791 "an attackId MUST NOT appear under more than one class". The same identifier twice inside one class is not addressed. **Choice:** not rejected (set semantics everywhere downstream). Class codes may be any string; a class with an empty array is legal as long as the manifest declares at least one identifier in total (L969–L977).

**N16. `networkPosture` extra members.** L268–L273: version 2 binds "the canonical digest of the carried networkPosture object", "any further member a producer carries there". **Choice:** the whole carried object is canonicalized; an extra member added after arming breaks the binding (tested).

**N17. Vocabulary arrays.** L796–L804: both arrays sorted ascending by UTF-16 code unit, no duplicates, BMP-only, `caught ⊆ labels`. Empty arrays are not forbidden. `caught == labels` is legal (tested). The BMP rule means code-point order and code-unit order coincide; the sort key used is nevertheless the UTF-16BE encoding, so the manifest and payload surfaces (where supplementary characters are legal in values) sort per RFC 8785 too.

### coverage

**N18. Classes outside the manifest.** L911–L916 "The three sets are a disjoint partition of the manifest's classes … A class in more than one of the three, or a manifest class in none, is malformed". A class code that is not a manifest class is not addressed. **Choice:** malformed (`coverage-unknown-class`): a partition of the manifest's classes has no room for a foreign class, and fail-closed is the spec's default. A class repeated inside `assessedClasses` counts as "in more than one" (`coverage-partition-violation`).

**N19. Coverage integrity.** L963–L964 "the union of attackIds for the assessed classes must exactly equal the manifest's". **Reading:** the set of row `attackId`s equals the union of `manifest.classes[c]` over `coverage.assessedClasses`. A row for an attack in a disclosed (`outOfScope`/`routedElsewhere`) class therefore fails integrity.

### attackResults

**N20. `actualLayer` on a clean row.** L1278–L1281 "the producer MUST emit the literal string `none`"; L1270–L1272 only a *missing* member is called malformed. **Choice:** a clean row whose `actualLayer` is a string other than `none` is malformed (`actual-layer-not-none`): the MUST is stated and nothing says a verifier may ignore it. A reading that only rejects absence would accept it.

**N21. Fail-closed members.** L1093–L1097: `basis`, `method`, `attribution` "a missing value, or any value outside them, is fail-closed … the row forces `result` to `fail`". L921–L923: `containmentObserved` outside the carried labels is fail-closed. **Choice:** a missing, non-string or out-of-vocabulary value in any of the four makes the row fail-closed: the statement stays valid and `result` must be `fail`. Exception, L760–L764: "A `basis: substrate` row whose `containmentObserved`, `basis`, or `method` is fail-closed … cannot satisfy the class-match requirement and is therefore invalid" — implemented for `containmentObserved` and `method` (`substrate-row-fail-closed`). `attribution` is deliberately not in that list, so an out-of-vocabulary `attribution` on a substrate row only forces `fail` (the class-match reads caught/clean and `method`, not `attribution`). A row whose `basis` is invalid is not a substrate row.

**N22. "MUST declare `paired`".** L618–L619 "A row whose `attackId` carries no such entry MUST declare `paired`." **Choice:** enforced as "must not declare `pinned`" (the pinned rule's second part); an out-of-vocabulary attribution there is handled by N21, not as a second violation.

**N23. `observationRefs`.** Optional on rows that are not `basis: substrate` (L947–L948 "Wherever `observationRefs` is present"); when present it must be an array of integers (a JSON `1.0` or `true` is not an integer index) and every index in range (L947–L952), on any row. Duplicate indexes are not forbidden; since 2026-11-20 a repeated index resolves its record once (no rule reads how often an index repeats; measured on cbb79e5 with a row citing its two records 1000, 2000 and 20000 times each: 0.093 s, 0.34 s and 35.89 s, the arming-against-seal comparison being quadratic; 0.07 s for the last with the fix). `observationSelectors` (L953–L958) is not read at all, not even for its type: "nothing normative reads it".

**N24. Rows of invalid shape.** `attackId` not a string → malformed (`row-attack-id-malformed`); not in the manifest → malformed (L919 "must appear in the manifest"), beside the coverage-integrity failure that follows.

### result

**N25. Recompute inputs when the vocabulary is malformed.** The recompute reads the carried arrays (L440–L442). When those are malformed the statement is already invalid; the recompute is skipped rather than run on garbage, and `result` is reported as `null`.

**N26. Fail-closed rows in condition three.** L447–L450 "any clean row … carries a `basis` other than `substrate` or a `method` other than `intercepted`" — a row with a valid clean label and an invalid `basis` satisfies this literally and also condition one; the minimum is `fail` either way.

### observationRecords

**N27. Envelope structure versus "covers nothing".** L1300–L1302 `payload`, `payloadType`, `signatures` (≥ 1 entry) are the envelope; L1316–L1318 say a record "whose payload is not so parseable, or whose media type is not `+json`, covers nothing". *A payload that is not base64, a non-string `payloadType` or an empty `signatures` array leaves no PAE bytes to hash, so `batchRoot` cannot even be recomputed.* **Choice:** envelope-level defects make the statement malformed (`observation-records-malformed`); payload-content defects make the record cover nothing. Base64 is accepted in the standard or URL-safe alphabet, with or without padding (DSSE envelope.md / protocol.md).

**N28. `+json` suffix.** L1316 "whose media type ends in `+json`". **Choice:** the string must end with `+json`, compared case-insensitively (RFC 6838 §4.2: type and subtype names are case-insensitive). A media type with parameters (`…+json; charset=utf-8`) does not end in `+json` and covers nothing.

**N29. Byte-identical entries.** L1750–L1752 "a record's canonical identity is its leaf hash". **Choice:** two entries with the same leaf hash (same `payloadType` and payload bytes, whatever their `signatures`) make the statement invalid (`duplicate-record`).

**N30. `batchRoot` with an empty array.** L1742 "required when `observationRecords` is non-empty"; L1749 "an empty array with no root"; L1767 "omitted only when `observationRecords` is absent". *The three sentences disagree on `observationRecords: []`.* **Choice:** `[]` behaves like absent: no root recomputes, so a carried `batchRoot` beside an absent or empty array is invalid (`batch-root-unexpected`).

**N31. Which records the universal kind check reaches.** L595–L598 "every carried record that binds to this run and whose payload `aeeKind` names a covering kind … satisfies every constraint of that kind". **Choice:** "binds to this run" = payload parses as a canonical `+json` object and its `aeeRunBinding` equals the derived digest. `aeeMethod` is not part of the binding: on a bound `arming`, `sealed` or `examination` record a missing or unregistered `aeeMethod` violates that kind's `aeeMethod` constraint (L1329, L1335, L1337) and invalidates the statement like any other constraint (corrected after review: the first build left such a record out of the check, so a carried seal reporting its moat down escaped it by also dropping `aeeMethod`). A record of another run is ignored unless a substrate row references it (then `run-binding-mismatch`). A record whose payload is not canonical `+json`, or whose `aeeRunBinding` is missing, is not "bound" and is likewise ignored unless referenced — with two exceptions that read the kind only: an `interception` must be resolved by a caught row (L580–L585) and the `aeeObservedSet` recompute counts every record whose parsed kind is `interception` or `examination` (N33). When no row is `basis: substrate` there is no binding (L224–L225) and the universal check does not run; `batchRoot`, duplicates, interception resolution, the clean-row rule, `aeeObservedSet` equality and the `pinned` rules still apply because none of them needs the binding.

**N32. Constraints of the `sealed` kind.** L1330–L1335 list the typed members; L1361–L1366 say a seal "covers no clean row unless its `aeeStillArmed` is `true`, its `aeeDropCount` is zero or does not exceed an `aeeDropBound` …, and its `aeePostureDigest` equals the pinned `networkPosture` digest". *Are those covering conditions "constraints of its kind" for the existence requirement (L586–L589) and the universal partner (L595–L608)?* The universal partner's own example is "a substrate signs a `sealed` record reporting its moat down … and the run reads clean with the record that says otherwise sitting in the statement" (L600–L603), and L637–L639 "a statement whose only seal reports its moat down is not repaired by dropping the seal". **Choice:** yes — a bound seal with `aeeStillArmed: false`, an unbounded non-zero drop count or a posture digest different from the pinned one invalidates the statement (`sealed-record-invalid`), and if no other seal is valid the existence requirement fails too (`sealed-record-missing`, N38).

**N33. `aeeObservedSet` recompute set.** L1499–L1505 "every `interception` and `examination` record the substrate emitted for this run … A verifier recomputes the same value over the carried records of those two kinds". **Choice:** over every carried record whose parsed `aeeKind` is one of the two, regardless of its binding or of its own validity; `moat-drop`, `uncommitted-observation`, `arming`, `sealed` and unknown kinds are excluded (L1400–L1403). L609 "on every carried `sealed` record" is applied to every parseable sealed record, bound or not.

**N34. Sealed posture versus arming posture on the row-free check.** L1370–L1373 "which `arming` records supply the set on a check that reads no row is not stated here and is not settled by it." **Choice:** the row-free (universal) check compares the seal only against the pinned `networkPosture` digest; the per-row check additionally compares against each `arming` record the row resolves. Since every bound arming record must itself equal the pinned digest, the two readings coincide on any statement that passes the universal check.

**N35. `aeeDropCount` sign.** L1331 "an integer counting run-wide dropped observations". No non-negativity rule is stated. **Choice:** none invented; the covering rule is applied literally (`== 0` or `<= aeeDropBound`). A JSON `true`/`false` is not an integer. `aeeDropBound`, when present, must be an integer.

**N36. `aeeAssessedAttacks` with several arming records.** L1471–L1473 "The union of the manifest's identifiers for the carried `coverage.assessedClasses` MUST be a subset of this array". L1186–L1188 permit several arming records. **Choice:** the subset rule is checked against every bound, valid arming record (`assessed-attacks-not-declared`).

**N37. `aeeObservedAttacks` obligation.** L1539–L1542 "For every identifier in the array the statement MUST carry an `attackResults` row with that `attackId` whose `containmentObserved` is in the carried caught set". **Choice:** checked on every bound sealed record; a caught row of any `basis` satisfies it (the text says nothing about basis).

**N38. Primary condition.** L631–L644: when no carried seal satisfies every constraint, "A verifier SHOULD report the unmet existence requirement as its primary condition and any refusal naming the defective record's kind beside it rather than in its place". **Implemented:** both codes are emitted and `primaryCode` is `sealed-record-missing`. L1403–L1408: a row resolving only `moat-drop` / `uncommitted-observation` SHOULD be refused "under a condition naming the kind rather than under its unrecognized-kind condition" — `row-resolves-non-covering-kind` is emitted beside `class-match-failed`; a row resolving only unknown kinds gets `row-resolves-unrecognised-kind`.

**N39. Unrecognised `aee*` payload members.** L1721–L1724 "this predicate is fail-closed (a colliding or unrecognized `aee*` member can only weaken coverage, the record covering nothing, never create it)". **Choice:** any payload member beginning with `aee` that this document does not define makes the record cover nothing, which under N31 invalidates a bound covering-kind record. A defined reserved member carried on a kind that does not require it (e.g. `aeePayloadCommitment` on an `uncommitted-observation`, L1431–L1438 "stated and not gated") is not penalised. `aeeVersion` (L1694, "reserved for a payload contract version") is recognised and carries no constraint.

**N40. `aeeBindingVersion`.** L241–L247: the arming record MAY carry it; a version the verifier does not implement is rejected "distinguishably from a run-binding digest mismatch". **Choice:** when present it must be the string `"2"` (the binding pre-image carries it as a string, L176); anything else is `binding-version-unsupported`, and the record covers nothing. The member is only read on `arming` records (where the text places it).

**N41. Referenced non-covering records.** L561–L564 "every referenced payload parses as a canonical `+json` object …, carries the reserved members, and its `aeeRunBinding` equals the run binding digest". **Choice:** applied to every record a substrate row resolves, including `moat-drop`, `uncommitted-observation` and unknown kinds (they must still parse, carry the reserved members and bind). A `moat-drop` beside a valid interception is fine; alone it leaves the row uncovered (N38).

**N42. Class match for reconstructed rows.** L554–L560: a `method: reconstructed` row "references at least one `examination` record" — stated for the method, not for caught/clean. **Choice:** a clean reconstructed row needs only an examination record (no `arming`/`sealed`); a caught reconstructed row likewise, and may additionally cite a reconstructed interception (the method cap allows it).

**N43. Method cap set.** L565–L566 "the weakest `aeeMethod` across its covering records". **Choice:** across the resolved records of covering kinds; `moat-drop` and `uncommitted-observation` are excluded (L1399 "MUST NOT admit either into the method cap").

**N44. `pinned` on non-substrate rows.** L614–L618 "a row declaring `attribution: pinned` resolves at least one `observationRefs` index to an `interception` record …" is stated over rows, not over substrate rows. **Choice:** applied to every row.

**N45. Interception identity for the pinned / unresolved rules.** "an `interception` record" is identified by its parsed `aeeKind`, whether or not the record is otherwise valid (an invalid one fails elsewhere).

### Timestamps

**N46. Profile details.** L1784–L1802: uppercase `T` and `Z`; zone `Z`, `+00:00` or `-00:00`; "RFC 3339 outside this profile is malformed". RFC 3339 allows an optional fraction and `time-second` 00–60. **Choice:** fraction accepted (any number of digits), second `60` accepted syntactically, calendar validity enforced (month, day-of-month, leap years). `armedAt <= issuedAt` is compared as instants (all UTC), fractions included.

### Evidence tier and keys

**N47. Key algorithm.** README L25–L26: keys arrive as `{"keyid": …, "publicKeyHex": …}`; L1907 (non-normative) `"<ed25519-public-key-bytes>"`. **Choice:** a 32-byte `publicKeyHex` is a raw Ed25519 public key; any other length is skipped with a warning. Verification is RFC 8032 (cofactorless group equation, canonical `s < L`, canonical point encodings).

**N48. "every covering record's signature verifies".** L769–L771. **Choice:** the covering records of a row are the records it resolves whose kind is a covering kind; a record verifies when at least one of its `signatures` verifies against any pinned key (DSSE multi-signature). `keyid` only orders which key is tried first (L1902–L1903 "an unauthenticated lookup hint and never the check itself"). A row with no key policy, or whose covering record does not verify, is `unattested`. Limits on the signatures tried: N63; the refinement `attested-sealed`: N64.

**N49. Tier of a fail-closed-basis row.** L767–L769 define `declared` for `basis: artifact` and the other two for `basis: substrate`; a row whose `basis` is out of vocabulary has no tier in the text. **Choice:** `declared` (it "sits at the bottom of both orderings", L1123, where artifact ranks).

**N50. Unusable key policy.** `AEE_SUBSTRATE_KEYS` set but unreadable, not JSON, or without the array: treated as "no pinned key" (every substrate row `unattested`) with a warning on stderr — fail-closed rather than an error exit, so the vector still receives a verdict.

### Things the text says that a builder may trip on

**N51. Two version numbers.** L3–L5: predicate type `…/v0.7`, "Version: 0.7.0"; the repository tag and the README say 0.12.1. The wire value checked is the type URI `…/v0.7`; 0.12.1 is the suite's revision, not a predicate version.

**N52. The schema example is not a vector.** L1806–L1809: only `corpus.digest` of the example is re-derivable; "the remaining digests are placeholders", and the record payloads are placeholders too, so the example cannot be used as a positive test.

**N53. "0.7 adds four members" counts.** L663 "Each of the four members 0.7 adds" and L1449 "Four reserved members carry the commitments this version adds" (`aeePayloadCommitment`, `aeeAssessedAttacks`, `aeeObservedSet`, `aeeObservedAttacks`) — consistent, but `attribution` and `expectedPayloads` are also new in 0.7 and are counted elsewhere (L2197 "Three members become REQUIRED"). Not a rule conflict, but the counts refer to different sets.

**N54. The `networkPosture` digest is both "no longer read verbatim" and "compared byte for byte".** L214–L217: the pinned digest is not a binding input any more, yet it is still compared against `aeePostureDigest` on arming and sealed records. Implemented exactly so; the sentence reads as a contradiction on first pass.

**N55. Floats that are integers.** In a canonical payload `1.0` cannot occur (JCS prints it as `1`), so `aeeRunSeq: 1.0` or `aeeDropCount: 1.0` is unreachable by a conforming producer; on the statement surface `observationRefs: [1.0]` is a malformed index (not an integer).

**N57. Decision on the review's reading of the universal kind check (patch 0003).** The first build (fea61aa) read L595–L598 "every carried record that binds to this run" as "every record carrying *all* the reserved members with a valid `aeeMethod` and the right binding", so a record with `aeeMethod` missing or outside `{intercepted, reconstructed}` fell outside the universal check. The review showed the consequence: a carried seal reporting its moat down (`aeeStillArmed: false`) was refused when its `aeeMethod` was `intercepted` and accepted when the member was dropped or set to `bogus`. Re-reading every occurrence of `aeeMethod`: L1329, L1334–L1335 and L1337 state the value as a constraint *of the kind* ("its `aeeMethod` MUST be `intercepted`"), L1349–L1353 say the member is "determined by `aeeKind` on every run-level kind", and L1344–L1347 say a record "violating any constraint of its declared `aeeKind` … covers nothing". Nothing in L595–L608 makes `aeeMethod` part of "binds to this run"; the binding is `aeeRunBinding` (L226–L230, L561–L564). A reading under which deleting a member takes a record *out* of a check is also the exact non-monotonic shape L600–L603 and L2224–L2235 are written against ("a constraint evaluated only where a row points is a constraint whose subject the producer chooses"). **Decision: the review's reading is accepted and applied.** "Binds to this run" = canonical `+json` object + `aeeRunBinding` equal to the derived digest; on such a record every constraint of its kind, `aeeMethod` included, is evaluated. While checking the patch a fourth case of the same shape was found and closed in the same way: a bound `interception` with `aeeMethod` missing or unregistered, cited only by an `artifact` caught row (so outside every per-row substrate check, L2232–L2233 "`interception` through a caught row of a basis the per-row requirements above do not reach"), passed the universal check because `interception` is the one kind whose `aeeMethod` is free (L1352) and the first build only checked its commitment array there. This fourth case is a reading rather than the text: the `interception` kind states one constraint of its own (L1322–L1323, `aeePayloadCommitment`), and the reserved members, `aeeMethod` among them, are required of a record "used to cover a `basis: substrate` row" (L1309–L1318), which this record is not. We read the member's vocabulary (L1341–L1342) and L1349–L1353 ("only `interception` leaves the member free", "an independent value on per-event records") as binding every run-bound interception, so a bound interception whose `aeeMethod` is missing or unregistered is now `interception-record-invalid`; a build that reads L1322–L1323 alone accepts that statement. What stays as read before: a record whose payload is not canonical `+json` or carries no `aeeRunBinding` cannot be told to bind to any run and is reached only when a row cites it (N28/N31).

**N56. Code-set comparison.** README L43–L45: a reject vector passes when the emitted codes intersect the expected set. Because this rail's names are its own (R5), a human mapping from these names to the registry is needed for that comparison; verdicts, `result` and `tiers` need none.

**N59. Unrecognized members are reported (2026-10-10).** N10 settles the verdict: a member this verifier does not read
is ignored (in-toto README "Consumers MUST ignore unrecognized fields"; L779–L781 for predicate-level `aee*` members).
Measured on 0ea2708: a statement, a `subject[0]` and a predicate carrying a member nobody defined each verified
`accept` with nothing in the output. **Choice:** the verdict and the codes do not move; the ignored names are written
to `notes` (one line per object: statement, `subject[0]`, predicate), so the reader sees what was not read. The
closed lists are `STATEMENT_MEMBERS`, `RESOURCE_DESCRIPTOR_MEMBERS`, `PREDICATE_MEMBERS` in `verifier.py`; `aee*`
payload members keep N39. Predicate-level members the spec reserves -- a carried `evidenceTier` and every member whose
name begins with `aee` (L779–L781: "MUST be ignored and MUST NOT alter the derivation") -- are ignored and, since
2026-11-20, named in a note of their own (`ignored predicate member(s) the spec reserves, per L779-L781 …`); measured on
a3e942e: `predicate.aeeInventato` and `predicate.evidenceTier` each gave `accept` with nothing in the output, the only
ignored members not named. The prefix is matched as written (`Aee…` is an unrecognized member, named as such).
Since 2026-11-20 the same is done inside the predicate (measured on cbb79e5: an unknown member added to
`observationEnvironment`, its `catchPolicy`, `coverage`, a row, a record envelope and a signature entry gave
`accept` with nothing in the output): `NESTED_MEMBERS` in `verifier.py` lists the members of
`observationEnvironment` and of its `substrate`, `catchPolicy`, `corpus`, `corpus.manifest`,
`observationVocabulary` and `runEntropy`, of `coverage`, of each `attackResults` row, of each
`observationRecords` envelope and of each signature entry (spec L783–L800, L874–L878, L905–L909, L918–L928,
L953; DSSE); any other member is named, one note per object kind. `networkPosture` is not listed: all its
members enter its digest (N16), which the records of the statement must carry; on a statement that carries no
record nothing compares that digest, and a member added there is not named (measured on 68c6507 with the
artifact-only scenario: `accept`, nothing in the output). DigestSets are not listed: they take any algorithm name.
A list of names longer than 160 characters is cut there and followed by the count of the names (`... (N in all;
list cut at 160 characters)`), in these notes and in the three of 2026-10-10; until 68c6507 the cut was silent, and
a member named `!` and 200 letters hid every other unread member of its object. The names are collected in time
linear in their number (68c6507: 40000 unread members in one row, 512.6 kB, 13.04 s; 0.20 s on cbb79e5). A signature
entry whose `sig` is not base64 of 64 bytes, or whose `keyid` is not a string, is named too (DSSE: one
verifying signature suffices, so neither moves the verdict or the tier).

**N60. Keys of small or mixed order in the key policy; entries the loader cannot use.** N47 reads a 32-byte
`publicKeyHex` as a raw Ed25519 key and verifies with the cofactorless RFC 8032 equation, which RFC 8032 allows for
any canonical point. Measured on 0d8cee1 (14 November 2026): the 29 "acceptable" cases of Wycheproof
`testvectors_v1/ed25519_test.json` (8 `SmallOrderPublicKey`, 21 `MixedOrderPublicKey`) all verify, and with the
identity point `01 00…00` in `AEE_SUBSTRATE_KEYS` a signature built with no secret (`R = [s]B`, `S = s`) verifies on any
message, so every substrate row would be attested by anyone. Wycheproof's notes: "Implementations may reject them under
a stricter public-key policy" (`SmallOrderPublicKey`), "implementations may reject them under a stricter subgroup
policy" (`MixedOrderPublicKey`). **Choice:** the key policy is the consumer's own trust input, so the stricter policy is
applied there: a key whose point has small order (`[8]A` is the identity) or a torsion component (`[L]A` is not the
identity) is skipped with a warning, like a key of the wrong length (N47) — fail-closed, it attests nothing. Signature
verification itself is unchanged (RFC 8032). A 32-byte `publicKeyHex` that decodes to no canonical point (RFC 8032
5.1.3: `y >= p`, `x = 0` with the sign bit set, or no square root) is skipped with a warning too; until 0d8cee1 it was
kept and verified nothing. Every other thing the loader does not use is warned about too: an entry that is not an
object, an entry member other than `keyid` and `publicKeyHex`, and a top-level member other than
`substrateObservationKeys` (named, the rest is still read). A member name repeated in one object, at any depth, makes
the policy unusable (no pinned key, with a warning; RFC 7493 2.3, as `strict_json` does for the statement): until
0d8cee1 the last one silently won, so a key could drop out without a word. A `keyid` that is not a string is warned
about and the key is kept: the keyid is only an ordering hint (`verifier.py`, signature loop); until 0d8cee1 it
silently became `""`.
Since 2026-11-20 the same policy is applied by `Verifier(keys)` itself (measured on cbb79e5: a caller of the
class passing the identity point got every substrate row `attested` by signatures made with no secret, while
the command line skipped the key). Kept: a pair whose key is 32 bytes decoding to a point of prime order;
every other entry is skipped and named in the notes; a `keyid` that is not a string is kept as `""` and
named; `keys` other than None, a list or a tuple is a TypeError.

**N61. One line per human-readable line (2026-11-20).** The notes and messages quote statement text. Measured on
cbb79e5: a statement member named `x\naccept: … (forged)\n{"verdict":"accept",…}` put a forged `accept:` line and a
forged JSON object above the real last line (which stayed right). **Choice:** every character of Unicode
category Cc, Zl or Zp (they include every line boundary of `str.splitlines`, and ESC) in a note, a message or a
warning is written as `\xNN` or `\uNNNN` (`cli.one_line`); nothing else is changed.
An input larger than the memory the process may use (measured on cbb79e5 with `/dev/zero` under
`ulimit -v 600000`: MemoryError traceback, exit 1 — the reject status — and no JSON line) is unreadable
input: exit 2, code `unreadable-input`, as for an OSError; the same when the input is read but the memory ends
while it is parsed or verified (measured on 68c6507: a 150 MiB file under `ulimit -v 600000` was still a traceback
and exit 1). Since then an input size limit is set too (N62).

**N62. Input size limit (2026-11-20).** The spec sets no limit on the size of a statement, and the README contract
("What the suite compares") none on the input file. Measured on 64227ea (CPython 3.11.2): `/dev/zero` as the input was
read until the memory ran out (under a 600 MB address-space limit: 586 MB resident, then exit 2; with no process limit
not measured, as it would take the machine's memory); a 16 MiB statement whose predicate carries an array of 8 million integers peaked at 760 MB of resident memory
and took 7.7 s (46 bytes of memory per input byte; 1 and 4 MiB: 0.5 and 1.9 s); the largest honest statement the test
builder makes (2000 caught rows, each with its own signed record) is 1.6 MB. **Choice (a consumer resource policy):**
the command line reads the input in chunks of 1 MiB and stops as soon as more than `AEE_MAX_INPUT_BYTES` bytes (default
16 MiB = 16777216) have been read: exit 2, code `unreadable-input`, the JSON line written, as for an unreadable file
(`/dev/zero` with no process limit: exit 2 after 0.22 s at 31 MB resident).
`Verifier(keys, max_input_bytes=…)` (same default) raises `InputTooLarge` on a longer input, so the library gives no
verdict either. The variable, when set, must be ASCII decimal digits of value at least 1; any other value (empty, a
sign, spaces, other digits, 0) is a bad invocation: exit 2, code `usage`, the variable named on stderr. Digits of any
number are read as their value: measured on d0b8d7a (CPython 3.9.25, 3.11.2, 3.13.15), a value of 5000 digits was a
`usage` error that did not name the variable (the interpreter refuses to convert more than 4300 digits at once);
since 2026-11-21 the value is built 4000 digits at a time.

**N63. Signature limits of the tier derivation (2026-11-20).** L769–L771 make a substrate row `attested` when every
covering record's signature verifies against a pinned key; DSSE (envelope.md "Multiple signatures", protocol.md
"Multi-signature Verification", read 2026-11-20 at secure-systems-lab/dsse `master`) lets an envelope carry any number of
signatures and sets no limit, and neither does the spec. Measured on 64227ea (CPython 3.11.2, three pinned keys; under
N48 each entry was tried against every key): 2000 entries that verify nothing and one good one on a record cost 6002
Ed25519 verifications, 12.4 s for 240.6 kB; the same 6000 failed verifications spread as 16 entries on each of 125
records, cited by 125 caught rows, 12.0 s for 317.5 kB; as one entry on each of 2000 records, 12.5 s for 1.56 MB. A limit
per record alone therefore bounds nothing per byte. An honest statement of 2000 records signed with the right keyid
costs 2000 verifications and no failed one (8.5 s for 1.58 MB). Envelopes seen: one signature per record in the spec's
examples (L362–L376), two in DSSE's multi-signature example. **Choice (a consumer resource policy, decided by Roberto
Locatelli on 2026-11-20):** (a) a record carrying more than `max_signatures_per_record` signature entries whose `sig` is base64 of 64 bytes
(default 16, 8 times the most seen; `AEE_MAX_SIGNATURES_PER_RECORD`; the other entries cost nothing and verify nothing,
N59, so they do not count) is not tried: it verifies nothing; (b) the failed Ed25519 verifications of the records that verify nothing are
counted, and once they reach `max_failed_verifications` (default 256, about 0.5 s at 2 ms each;
`AEE_MAX_FAILED_VERIFICATIONS`) no further record is tried and every record not yet decided verifies nothing. The limit
is checked before a record is tried, never in the middle of one, and the failed attempts of a record that then
verifies are not counted (since 2026-11-21; until then every failed attempt counted, see the measure below). Cost
bound: the records that verify nothing cost at most `max_failed_verifications` - 1 + `max_signatures_per_record` x the
number of pinned keys attempts; a record that verifies costs at most `max_signatures_per_record` x the number of pinned
keys, and only a payload a pinned key signed can verify (a payload is carried once: `duplicate-record`). Each case is
named in a note with the records it left untried. A limit can only take `attested` away (the row becomes `unattested`),
never give it; the verdict, the codes and `result` do not move. **This departs from L769–L771** for a statement over a
limit: there a row the spec would call `attested` is `unattested` (fail-closed, and named). Raising both limits above
the statement's counts restores the spec's derivation exactly. Order of the attempts (cost only: any order gives the same
answer below the limits): entries whose `keyid` names a pinned key first; for each entry the keys of that keyid first,
then the key that verified the last record, then the policy order; an entry whose `sig` is not base64 of 64 bytes is
not tried. After the change of 2026-11-20, on the same inputs: 1, 256, 256 verifications (0.09, 0.64,
1.13 s); the honest statement unchanged (2000, none failed; 2001 since N64, which verifies the seal once).
What the failed-verification limit cost an honest statement while every failed attempt counted (measured on d0b8d7a and
on 9970cde, three pinned keys, every record signed by a pinned key, default limits): records signed by one key, with
the policy's `keyid`, another or none: no failed verification (200, 300, 600 records); records signed by two or three
keys in turn carrying the policy's `keyid`: none; two keys in turn with no `keyid`, or with one the policy does not
use: one failed verification per record after the first, so of 300 rows 256 were `attested` and 44 `unattested` (of
600: 256); three keys in turn: 192 of 200. Since 2026-11-21 (the rule above), measured on generated honest
statements with 1 to 8 pinned keys signing in turn, `keyid` of the policy, absent or of another name, 1, 7 and 300
records (72 statements), and 2000 records with 3 and 8 keys (6 statements): every row `attested`, no limit note
(2000 records, 8 keys, no `keyid`: 9251 verifications, 7250 of them failed and not counted, 42 s). The hostile inputs
above after the change: 1, 288 and 258 verifications (16 entries on each of 125 records: 6 records of 48 failed
attempts; one entry on each of 2000 records: 86 records of 3).

**N64. A refinement of `attested`: `attested-sealed` (2026-11-20).** L766–L771: a substrate row is `attested` when every
covering record's signature verifies; the covering records are those the row resolves (N48). The `sealed` record a
statement with a substrate row must carry (L586–L589) is a covering record only of the rows that cite it (clean
intercepted rows), so a caught or reconstructed row is `attested` whatever the seal's signature. Measured on 00db9f1:
the test builder's default statement with the seal's signature replaced by 64 zero bytes gives the tiers `attested`,
`unattested`, `attested` and says nothing of the seal. L775–L778: "Consumer policy MAY subdivide `attested` into
stricter refinements …; a refinement refines, never reorders, the three tiers, and tier names beginning with `aee` are
reserved." **Choice (decided by Roberto Locatelli on 2026-11-20; the spec's `attested` is not changed):** a new,
named refinement `attested-sealed`: an `attested` row whose statement carries a `sealed` record that satisfies every
constraint of its kind, binds to this run and verifies against a pinned key. It is derived after the tiers, under the
limits of N63, and never moves the verdict, the codes, `result` or `tiers`: the JSON line keeps the spec's three tier
names (the harness contract compares them), the refined list is `Report.refined_tiers`, and one note says whether
the attested rows meet it (`refinement attested-sealed …: met by every attested row` / `not met by attested row(s)
…`). Measured over the whole test suite of 00db9f1 (262 tests, 565 distinct statement and key-policy pairs): the JSON line is identical on
00db9f1 and with the refinement for all 565; of the 406 `attested` rows, 400 are `attested-sealed` and 6 are not. The
spec's own test set was not run (not opened for this build: "Sources used" in the README), so whether one of its
vectors has an `attested` row that is not `attested-sealed` is not measured; by construction its expected tiers are
unaffected.

**N65. Signatures of the records that cover nothing (2026-11-20).** L1394–L1397: of `moat-drop` and
`uncommitted-observation` records, "A verifier MUST verify their signatures as it verifies any record's and MUST include
their leaves in the `batchRoot` recompute"; L1397–L1401: neither may satisfy any row's class-match requirement or enter
the method cap; L770: a row's tier reads its covering records only; L394–L397: the `result` recompute never reads a
signature outcome. Until this note the verifier verified signatures only where a tier read them, so these two kinds were
never verified (REQUIREMENTS said so). Measured on 64227ea and on 74dd0ba (`sonda_l1396.py`): for both kinds, cited by
a substrate row or not, a good signature, a signature of 64 zero bytes and a signature by an unpinned key gave the
same output (`accept`, the same tiers, no note). **Choice (the MUST is followed; what it changes is not stated by the
text):** with a key policy, every carried record whose `aeeKind` is one of the two is verified as any record is (N48,
under the limits of N63), after the tiers and the refinement of N64 so that it never takes a verification a tier
needs; a record that does not verify is listed in `Report.non_covering_unverified` and named in a note. Verdict,
codes, `result`, `tiers` and the refinement do not move: these kinds cover nothing, and the spec gives their
signature outcome no effect on any of them. Without a key policy nothing is verified (as for every record, L772–L774).
