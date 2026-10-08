# Requirement inventory — AEE predicate v0.12.1 (0.7.0)

Every normative sentence in `spec/adversarial-execution-evidence-v0.12.1.md`
(measured with `grep -nwE 'MUST|SHOULD|REQUIRED'`: 83 `MUST` of which 26
`MUST NOT`, 10 `SHOULD`, 3 `REQUIRED`), grouped by the party it binds, with
the line it sits on, the check that implements it and the code the check
emits.  "n/a" marks sentences that bind a producer or a downstream consumer
policy and have no verifier-side check by the spec's own design.

Codes are this verifier's names (the spec defines none); see README.md.

## 0. Use Cases (L65–L93)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L90–L92 | a consumer MUST NOT infer a composite guarantee from two attestations unless its policy binds both to the same execution | n/a (consumer policy across statements) | n/a |

## A. Statement bytes (Prerequisites)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L99–L102 | Producers MUST enforce the I-JSON safe-integer profile; integers ≥ 2^53 MUST be rejected | `strict_json` rejects such integer tokens statement-wide and in payloads (SPEC_NOTES N5) | `integer-out-of-safe-range`; payload: `referenced-record-unparseable` |
| L108 | verifier MUST reject a duplicate member statement-wide | parser | `duplicate-member` |
| L111–L113 | MUST reject any string literal not a well-formed scalar sequence; statement MUST be valid UTF-8, no overlong, no CESU-8 | strict UTF-8 decode of the raw bytes first | `invalid-utf8` |
| L114–L117 | high-surrogate escape MUST be followed by a low one; unpaired escape malformed; MUST NOT contain raw chars < U+0020 | parser | `ill-formed-string` |
| L117–L120 | `\u` escape MUST be exactly four hex digits (no sign, whitespace, radix) | parser | `ill-formed-string` |
| L120–L127 | noncharacters excluded at any depth, names and values | parser | `ill-formed-string` |
| L136 | MUST apply the check to the raw bytes before any decoded string is read | decode happens before parsing; parser works on the decoded text of validated bytes | — |
| L139–L148 | MUST reject nesting depth > 128 (outermost `{` = 1); payloads under the same bound | parser depth counter, per document | `nesting-depth-exceeded`; payload: `referenced-record-unparseable` |
| L150–L163 | signed canonical surfaces MUST be BMP-only; supplementary member name → payload covers nothing; supplementary vocabulary entry → malformed | `_names_bmp` on payloads; `is_bmp` on vocabulary arrays | `referenced-record-unparseable` / kind-invalid; `vocabulary-malformed` |

## B. Run binding and identity

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L174–L182 | binding digest = SHA-256 of JCS of the version-2 object | `_verify_predicate` derives it | `run-binding-mismatch` on records |
| L192–L197 | pre-image SHOULD fold in a public datable value | producer; not checkable | n/a |
| L210–L212 | `subject` MUST contain exactly one entry on any basis | `_verify_statement` | `subject-count` |
| L213–L218 | the six digests MUST be lowercase 64-hex | `_verify_environment`, subject check (N13) | `*-digest-malformed` |
| L224–L226 | artifact-only statements derive no binding, need not carry `runEntropy`; verifier derives the digest from the statement alone | binding derived only when a substrate row exists | `run-entropy-missing`, `run-binding-not-derivable` |
| L237–L247 | verifier MUST reject fail-closed a binding version it does not implement; explicit `aeeBindingVersion` read before deriving, rejected distinguishably | arming payload check (N40) | `binding-version-unsupported` |
| L268–L273 | binding covers the carried `networkPosture` object | canonical digest of the carried object | `run-binding-mismatch` |
| L303 | substrate SHOULD carry its own attestation | out of scope | n/a |

## C. Parsing rules and `result`

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L389–L392 | consumer MUST be able to recompute `result`; a `result` the recompute does not reproduce is invalid | `_recompute_result` vs carried | `result-mismatch`, `result-out-of-vocabulary` |
| L395–L397 | recompute never reads records, signatures or trust | implemented over rows + coverage only (tested with/without keys) | — |
| L433–L454 | `result` = min of three conditions over caught / fail-closed rows, coverage gaps, indirect clean rows | `_recompute_result` | `result-mismatch` |
| L483–L484 | consumer separating vantage from time MUST read the row members | n/a (consumer) | n/a |
| L492–L493, L495–L500 | consumer crediting a substrate row MUST derive the tier; relaxing below `pass` MUST key on row members | tier derived for every row; the rest is policy | tiers output |
| L539 | consumers MUST anchor identity on digests, not names | names never read (N14) | — |

## D. Coverage validity (per substrate row, L542–L567)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L552–L553 | `observationRefs` non-empty, every index in range | row loop | `substrate-row-no-refs`, `observation-ref-out-of-range` |
| L554–L560 | class match: caught+intercepted → interception; reconstructed → examination; clean+intercepted → arming + covering sealed | `_cross_checks` per row | `class-match-failed` (+ `row-resolves-non-covering-kind` / `row-resolves-unrecognised-kind`) |
| L561–L564 | every referenced payload canonical `+json`, reserved members, `aeeRunBinding` equal | per referenced record | `referenced-record-unparseable`, `run-binding-mismatch` |
| L565–L566 | `method` no stronger than weakest `aeeMethod` of covering records | per row | `method-cap-violation` |
| L567 | `batchRoot` recomputes | `_load_records` | `batch-root-mismatch`, `batch-root-missing` |
| L1031–L1033 | producer MUST NOT declare `basis: substrate` on a row it cannot cover; such a row makes the attestation invalid | same checks | as above |
| L760–L764 | substrate row with fail-closed `containmentObserved` / `basis` / `method` is invalid | row loop (N21) | `substrate-row-fail-closed` |

## E. Coverage validity (statement-wide, L569–L623)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L574–L579 | a clean row resolves no interception (any row) | `_cross_checks` | `clean-row-references-interception` |
| L580–L585 | every carried interception resolved by a caught row | `_cross_checks` | `interception-unresolved` |
| L586–L594 | substrate-carrying statement carries ≥ 1 valid, bound sealed record | `_cross_checks` | `sealed-record-missing` |
| L595–L608 | every bound covering-kind record satisfies its kind's constraints | `_check_kind` + `_cross_checks` | `interception-record-invalid`, `arming-record-invalid`, `sealed-record-invalid`, `examination-record-invalid` |
| L609–L613 | `aeeObservedSet` on every sealed record equals the recompute | `_check_kind` (N33) | `observed-set-mismatch` (+ `sealed-record-invalid`) |
| L614–L623 | `pinned` row: ≥ 1 interception, `expectedPayloads` entry, every interception carries a declared value; no entry → MUST declare `paired` | `_cross_checks` (N44) | `pinned-attribution-unsupported` |
| L625–L629 | consumer MUST evaluate these before consuming `result`; on failure `result` MUST NOT be consumed | reject → `result: null` | — |
| L631–L644 | SHOULD report the unmet existence requirement as primary beside the defective-kind refusal | `primaryCode` (N38) | `sealed-record-missing` primary |

## F. Evidence tier (L766–L781)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L767–L771 | per-row tier: `declared` / `attested` (every covering record verifies against a policy key) / `unattested` | `_derive_tiers` | `tiers` |
| L772–L774 | no pinned root → every substrate row `unattested`; MUST NOT infer the root from the predicate | keys only from `AEE_SUBSTRATE_KEYS` | — |
| L774–L775 | tier never alters `result` | recompute independent (tested) | — |
| L779–L781 | carried `evidenceTier` / predicate-level `aee*` members MUST be ignored | ignored (tested) | — |

## G. observationEnvironment (L783–L903)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L785–L808 | five required members; manifest with required `classes`; `catchPolicy` digest; closed posture with digest; vocabulary arrays sorted, duplicate-free, BMP-only, `caught ⊆ labels`, digest of `{"caught","labels"}` | `_verify_environment` | `observation-environment-malformed`, `substrate-digest-malformed`, `catch-policy-digest-malformed`, `corpus-malformed`, `manifest-malformed`, `network-posture-malformed`, `network-posture-digest-malformed`, `vocabulary-malformed`, `vocabulary-digest-mismatch` |
| L790–L791 | attackId MUST NOT appear under more than one class | `_verify_manifest` | `manifest-attack-in-multiple-classes` |
| L808–L810 | `runEntropy` required exactly when a substrate row exists | `_verify_predicate` | `run-entropy-missing`, `run-entropy-digest-malformed` |
| L810–L813 | `corpus.digest` re-derived from the embedded manifest | JCS digest compare | `corpus-digest-mismatch`, `corpus-digest-malformed` |
| L815–L821 | `expectedPayloads`: keys declared, arrays non-empty, sorted, duplicate-free, lowercase 64-hex | `_verify_manifest` | `expected-payloads-malformed` |
| L830–L839 | corpus carries the commitment in the substrate's canonical form | producer; "no verifier can check" | n/a |
| L847–L855 | posture vocabulary closed at four values; absent / non-string / other → malformed; minor versions MUST NOT redefine | `_verify_environment` | `network-posture-out-of-vocabulary` |
| L905–L916 | coverage partition: each manifest class in exactly one set | `_verify_coverage` (N18) | `coverage-partition-violation`, `coverage-unknown-class`, `coverage-malformed` |

## H. attackResults (L918–L1033)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L919–L928 | `attackId` in manifest; `containmentObserved` from carried labels (fail-closed); `basis`, `method`, `attribution`, `actualLayer` required | row loop; recompute | `row-attack-id-unknown`, `row-attack-id-malformed`, `actual-layer-missing`; fail-closed → `result` |
| L931–L940 | producer MUST NOT reference a record whose payload does not evidence the row's attack; checkable only on `pinned` | pinned rule; `paired` ungated | `pinned-attribution-unsupported` / n/a |
| L941–L946 | no duplicate `attackId` across rows | row loop | `duplicate-attack-id` |
| L947–L952 | every `observationRefs` index MUST be in range on any row | row loop | `observation-ref-out-of-range`, `observation-refs-malformed` |
| L953–L958 | `observationSelectors` producer vocabulary, nothing normative reads it | ignored | — |
| L963–L966 | union of row attackIds equals manifest attacks of assessed classes | `_verify_predicate` | `coverage-integrity-mismatch` |
| L968–L990 | manifest MUST declare ≥ 1 attack identifier | `_verify_manifest` | `manifest-no-attacks` |
| L1081–L1082 | consumer MUST NOT move `result` or tier on attribution tolerance | nothing reads it | — |
| L1093–L1097 | `basis`, `method`, `attribution` REQUIRED, closed; missing/unknown → fail-closed row | `_row_info` + recompute | `result-mismatch` when carried result disagrees |
| L1117, L1147 | `fail` with artifact-only support SHOULD be read weaker; `reconstructed` clean rows SHOULD be read as tolerating transients | consumer guidance | n/a |
| L1199–L1200 | observation key MUST NOT be accessible to the artifact, SHOULD be held apart | deployment | n/a |
| L1248–L1251 | key validity window MUST use `armedAt`, MUST NOT use `issuedAt` | consumer policy (no window implemented) | n/a |
| L1278–L1281 | clean row MUST carry `actualLayer: "none"` | row loop (N20) | `actual-layer-not-none` |

## I. observationRecords (L1298–L1741)

| Line | Requirement | Check | Code |
|------|-------------|-------|------|
| L1300–L1302 | `payload`, `payloadType`, `signatures` (≥ 1 entry) | `_load_records` (N27) | `observation-records-malformed` |
| L1310–L1318 | covering payload canonical RFC 8785, valid I-JSON, BMP names, `+json` media type, reserved members; otherwise covers nothing | `_parse_payload` | `referenced-record-unparseable` / excluded from covering |
| L1320–L1340 | reserved members per kind: interception `aeePayloadCommitment`; arming `armedAt` (profile, ≤ `issuedAt`), `aeePostureDigest` = pinned, `aeeAssessedAttacks`, `aeeMethod` intercepted; sealed `aeeStillArmed` bool, `aeeDropCount` int, `aeePostureDigest`, `aeeObservedSet`, `aeeObservedAttacks`, optional `aeeDropBound`, `aeeMethod` intercepted; examination `aeeMethod` reconstructed (payload SHOULD identify states: not checked) | `_check_kind` | `*-record-invalid` |
| L1344–L1347 | a record violating any constraint of its kind covers nothing | `kind_valid` | as above |
| L1361–L1373 | sealed covers no clean row unless armed, drop count within bound, posture equal to pinned and to each resolved arming | `_check_kind` + per-row seal selection (N32, N34) | `sealed-record-invalid`, `class-match-failed` |
| L1375–L1408 | `moat-drop`, `uncommitted-observation` cover nothing; MUST verify their signatures, MUST include leaves in `batchRoot`, MUST NOT class-match, MUST NOT enter the method cap, MUST NOT enter `aeeObservedSet`; SHOULD name the kind in the refusal | `_cross_checks`, `_evaluate_payloads`; signatures: verified on the same terms as every record, i.e. only where an output reads them (the tier of covering records), so a non-covering record's signature is never checked and no output depends on it | `row-resolves-non-covering-kind` |
| L1431–L1438 | producer MUST NOT put `aeePayloadCommitment` on an `uncommitted-observation` ("stated and not gated") | not gated, per the text | n/a |
| L1454–L1458 | `aeePayloadCommitment` non-empty, sorted, duplicate-free, lowercase 64-hex | `_check_kind` | `interception-record-invalid` |
| L1467–L1473 | `aeeAssessedAttacks` sorted, duplicate-free, declared identifiers; assessed union MUST be a subset | `_check_kind`, `_cross_checks` (N36) | `arming-record-invalid`, `assessed-attacks-not-declared` |
| L1499–L1508 | `aeeObservedSet` = SHA-256 of JCS of sorted leaf hashes of interception + examination records; mismatch → invalid | `_evaluate_payloads` | `observed-set-mismatch` |
| L1522–L1533 | seal signed after every record; every drop site MUST increment `aeeDropCount` | producer; "neither is checkable" | n/a |
| L1535–L1542 | `aeeObservedAttacks` sorted, duplicate-free, declared; every identifier MUST have a caught row | `_check_kind`, `_cross_checks` | `sealed-record-invalid`, `observed-attack-without-caught-row` |
| L1611–L1650 | optional `aeeRunSeq` / `aeePrevRunBinding` / `aeeChainScope` syntax; `aeeChainScope` REQUIRED with `aeeRunSeq`; closed token vocabulary (MUST NOT redefine); any violation → covers nothing | `_check_kind` | `arming-record-invalid` |
| L1687–L1690 | unrecognised kind covers nothing, is otherwise ignored, still contributes its leaf; minor versions MUST NOT change covering semantics | `_load_records`, `_cross_checks` | — |
| L1693–L1703 | `aee` prefix reserved; producer members MUST NOT affect validity, `result`, tier; verifier MUST NOT rank them | only reserved names are read (tested with ordered producer members) | — |
| L1721–L1724 | unrecognised `aee*` member → record covers nothing | `unrecognised_reserved` (N39) | `*-record-invalid` |
| L1742–L1770 | `batchRoot` RFC 6962, domain-separated, recursive split, leaves in order, single leaf = root, empty = no root; byte-identical entries invalid; required when records non-empty | `merkle_root`, `_load_records` | `batch-root-missing`, `batch-root-mismatch`, `batch-root-unexpected`, `duplicate-record` |
| L1775–L1782 | `doesNotAssert` advisory; verifier MUST NOT require it; `does_not_assert` not an alias | optional; retired spelling rejected (N10, N12) | `does-not-assert-malformed`, `retired-spelling` |
| L1784–L1802 | `issuedAt` RFC 3339 UTC, uppercase `T`/`Z`, zone `Z`/`+00:00`/`-00:00`; `armedAt` same profile | `timestamp.parse_profile` | `issued-at-malformed`, `arming-record-invalid` |

## J. Consumer policy obligations (L1811–L1894) — not validity

| Line | Requirement | Status |
|------|-------------|--------|
| L1822–L1835 | MUST pin corpus and substrate digests out of band and compare; SHOULD expose one conjoined admission result | Not implemented: no anchor channel exists in the harness contract (README L170–L174 confirms these are consumer-policy facts outside the verdict). |
| L1837–L1864 | MUST pin demanded classes; MUST record a "no class demanded" decision explicitly, MUST NOT fold it into the anchor pins | Not implemented (same reason). |
| L1866–L1894 | MAY require `pinned` / non-empty `aeeObservedAttacks`; SHOULD say so in the admission result | Not implemented; row members and the seal's array are available in the statement for a policy layer. |
| L1939–L1940 | policy admitting `pass_indirect` MUST keep the live-observation rule | consumer policy | n/a |

## K. Changelog restatements

L2012, L2036, L2198, L2305 restate rules already listed above (validity gate precedence, canonical `+json` payloads, members becoming REQUIRED in 0.7, producer territory inert); no additional check.

## Count

Measured: 83 `MUST` (26 of them `MUST NOT`), 10 `SHOULD`, 3 `REQUIRED` in the
spec text; 75 distinct condition codes emitted by the verifier (counted from
the sources on 2026-10-08).  The tables above map every normative sentence to
a check or to "n/a"; the n/a rows bind producers, substrates or downstream
consumer policy and have no verifier-side check by the spec's own design.
The mapping is a hand classification, not a measurement.
