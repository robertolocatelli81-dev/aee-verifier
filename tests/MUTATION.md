# Mutation testing — positive control of the test-suite

`tests/mutate.py` mutates the sources one site at a time (drop a
`rep.fail(...)` / `problems.append(...)`, flip a comparison, `and`/`or`,
drop a `not`, swap `any`/`all`, bump a small constant, flip a boolean) and
runs the whole suite (every `tests/test_*.py` file) in an
isolated copy of the repository.  A mutant that passes the suite has
survived.  Re-measured 2026-10-21 UTC after the integer bound in
`jcs.format_number` (3 new sites, all killed) on top of the ignored-member
notes of SPEC_NOTES N59 (6 new sites in `verifier.py`, all killed),
CPython 3.11.2, 3 jobs.
Earlier: 2026-10-08 after the review fixes and the builder's follow-up fix
(interception without `aeeMethod`), 863 / 819 / 44; the first build,
fea61aa, 846 / 802 / 44; the reviewed series alone, 861 / 817 / 44.

| Module | Sites | Killed | Survived |
|--------|------:|-------:|---------:|
| `verifier.py` | 548 | 523 | 25 |
| `strict_json.py` | 128 | 124 | 4 |
| `jcs.py` | 50 | 45 | 5 |
| `timestamp.py` | 49 | 47 | 2 |
| `ed25519.py` | 77 | 71 | 6 |
| `cli.py` | 20 | 18 | 2 |
| **Total** | **872** | **828** | **44** |

Earlier rounds found real holes, since closed by added tests: `all`→`any`
on mixed-validity arrays (expectedPayloads, aeePayloadCommitment, signatures,
`is_bmp`), DSSE-envelope input defects, environment members missing on
artifact-only statements, the method cap with two interception records, a
manifest class disclosed nowhere with otherwise consistent rows,
`caught == labels`, depth accounting after a closed sibling container, U+0020
escaped by JCS, 30 February in a leap year, Ed25519 non-canonical point
encodings and `_equal` with `or`.

The review before posting found three survivors of the first build that
were listed below as equivalent and are not: `validate=True` in
`decode_base64` (the regex then admitted a final newline, which only
`validate` refused; the regex is now anchored with `\Z` and a test pins
it), `s >= L` in Ed25519 (with the identity as key and R, S = L verifies
under the mutant; now tested) and `all` over row attackId types (with
`any`, an array attackId raised TypeError; now tested).  A fourth hole
opened by the review fixes themselves (`bound` with `or`) is closed by a
test as well.

## Survivors, classified

Line numbers refer to the committed sources.

### `verifier.py` (25)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L77 | `<=` → `<` in `is_bmp` | equivalent | U+FFFF is a noncharacter, already rejected by the parser; no string reaching `is_bmp` contains it. |
| L103 | `validate=True` → `False` | equivalent | The regexes above it are anchored with `\Z` and admit only the alphabet plus up to two `=`; `validate` has nothing left to reject (490,000 sampled strings agree). |
| L145 | `reserved_ok = False` initial → `True` | equivalent | Overwritten whenever the payload parses; `usable` also requires `parsed is not None`. |
| L511, L514, L543, L571 | `ok = False` → `True` | verdict-equivalent | Short-circuit flags inside the environment and coverage checks; the failing code is already recorded, continuing only adds codes. |
| L588 | `counts.get(c, 0)` → `get(c, 1)` in the message `%d` | message-only | The condition is on the line above; this is the count printed in the message. |
| L589 | `partition_ok = False` → `True` | verdict-equivalent | The partition violation is already recorded; continuing runs coverage integrity too. |
| L658 | `ok = False` → `True` after a signatures defect | verdict-equivalent | `observation-records-malformed` already recorded; PAE bytes are still computable because payload/payloadType were valid in that branch. |
| L696 | `and` → `or` in the kind-check guard | equivalent | A record without a parsed payload has `parse_problem` set and no kind, so no new record reaches `_check_kind` with `parsed` unset; the problems it records on other records are read only through `parse_problem is None` / `usable` gates. |
| L706, L709 | `or` → `and` on `parse_problem` text | message-only | Selects which description is kept. |
| L829 | `and` → `or` in `resolved()` range filter | equivalent | Out-of-range references set `refs` to `None` earlier, so every index reaching here is in range. |
| L923 | `or` → `and` in a message | message-only | Fallback text of `referenced-record-unparseable`. |
| L924, L927, L929 | `row_ok = False` → `True` | verdict-equivalent | The code is recorded before the flag; continuing runs class-match on the same row and adds codes. |
| L934, L951 | `unknown` list / `elif unknown` with `or` | diagnostic-only | Only changes when the auxiliary `row-resolves-unrecognised-kind` code is added beside `class-match-failed`. |
| L944 | `all` → `any` on seal-vs-arming posture | equivalent | Every bound arming record must already equal the pinned digest (universal check), so all resolved armings share one posture. |
| L972 (×4) | key ordering by `keyid` hint | equivalent | The hint only orders the attempts; every pinned key is tried. |

### `strict_json.py` (4)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L42 | `pos: int = -1` default → `-2` | equivalent | Default never read for behaviour. |
| L279 (×3) | length pre-check: sign offset `1`→`2`, `0`→`1`, threshold `16`→`17` | equivalent | The pre-check only keeps tokens of more than 4300 digits away from `int()`; a shifted threshold hands tokens of 16-18 digits to the exact `abs(value) >= 2**53` check on the next lines, which decides them identically. |

### `jcs.py` (5)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L100, L101 | `x < 0` → `<=` | equivalent | `x == 0` returns `"0"` on L98 before either line. |
| L107 | `-6 < n <= 0` → `<= 1` | equivalent | `n == 1` is taken by the `0 < n <= 21` branch above. |
| L111 (×2) | `e >= 0` → `e > 0`; `0` → `1` | equivalent | Exponent form is only reached with `n > 21` or `n <= -6`, so `e = n - 1` is never 0. |

### `timestamp.py` (2)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L25 | `_DAYS[0] = 0` → `1` | equivalent | Index 0 is never used (`1 <= mo <= 12` checked first). |
| L52 | pad width `64` → `65` | equivalent | Both operands of every comparison are padded identically. |

### `ed25519.py` (6)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L36 | `(P + 3) // 8` → `(P + 4) // 8` | equivalent | `P + 3 ≡ 0 (mod 8)`, so the floor division yields the same exponent. |
| L115 | `return False` → `True` in the defensive `except` | equivalent | No input reaches the handler (all decoding paths return `None`/`False` explicitly). |
| L130, L139 | `h[:32]` → `h[:33]` | equivalent | The extra byte sits above bit 255 and is cleared by the clamp that follows. |
| L131, L140 | `(1 << 254) - 8` → `(2 << 254) - 8` | equivalent | The two masks differ only in bit 254, which the next line sets to 1 unconditionally. |

### `cli.py` (2)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L74 | `ensure_ascii=False` → `True` | equivalent | Produces an escaped but JSON-identical last line. |
| L98 | `or "-"` → `and "-"` | message-only | Human-readable accept line only. |
