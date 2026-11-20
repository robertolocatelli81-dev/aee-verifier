# Mutation testing — positive control of the test-suite

`tests/mutate.py` mutates the sources one site at a time (drop a
`rep.fail(...)` / `problems.append(...)`, flip a comparison, `and`/`or`,
drop a `not`, swap `any`/`all`, bump a small constant, flip a boolean) and
runs the whole suite (every `tests/test_*.py` file) in an
isolated copy of the repository.  A mutant that passes the suite has
survived.  Re-measured 2026-10-21 UTC after the integer bound in
`jcs.format_number` (3 new sites, all killed) on top of the ignored-member
notes of SPEC_NOTES N59 (6 new sites in `verifier.py`, all killed),
CPython 3.11.2, 3 jobs; `cli.py` and `ed25519.py` re-measured 2026-11-14 after SPEC_NOTES N60
(`ed25519.point_class`: 3 new sites; the key-policy loader: 6 new sites; all killed), CPython 3.11.2, 4 jobs.
`verifier.py`: the 3 sites of the negative `aeeDropCount` rule (2026-11-15) measured on 2026-11-16, all killed
(`<` → `<=`, `0` → `1`, the `problems.append` dropped); the other 548 sites are the code measured on 2026-10-21 and
were not run again. Survivor line numbers below L800 are unchanged, above it they moved by 4.
2026-11-20: the fixes of `tests/test_fix_20261120.py` added lines to `verifier.py` and `cli.py`. The table below still
gives the counts measured on cbb79e5; on this tree `tests/mutate.py` finds 574 sites in `verifier.py` and 30 in
`cli.py` (911 in the six modules), and only the sites on the changed lines were run (last section: 27 and 5); the
others were not run again. The survivor lines of `verifier.py` and `cli.py` below are renumbered to this tree
(same code, moved lines); two rows of cbb79e5 are gone: L833 (`and` → `or` in the `resolved()` range filter: the
line was rewritten and its mutant is now killed) and L948 (`all` → `any` on seal-vs-arming posture: rewritten, now
L1063 in the last section).
Earlier: 2026-10-08 after the review fixes and the builder's follow-up fix
(interception without `aeeMethod`), 863 / 819 / 44; the first build,
fea61aa, 846 / 802 / 44; the reviewed series alone, 861 / 817 / 44.

| Module | Sites | Killed | Survived |
|--------|------:|-------:|---------:|
| `verifier.py` | 551 | 526 | 25 |
| `strict_json.py` | 128 | 124 | 4 |
| `jcs.py` | 50 | 45 | 5 |
| `timestamp.py` | 49 | 47 | 2 |
| `ed25519.py` | 80 | 74 | 6 |
| `cli.py` | 26 | 24 | 2 |
| **Total** | **884** | **840** | **44** |

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

### `verifier.py` (23 of the 25 of cbb79e5; lines of this tree)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L111 | `<=` → `<` in `is_bmp` | equivalent | U+FFFF is a noncharacter, already rejected by the parser; no string reaching `is_bmp` contains it. |
| L137 | `validate=True` → `False` | equivalent | The regexes above it are anchored with `\Z` and admit only the alphabet plus up to two `=`; `validate` has nothing left to reject (490,000 sampled strings agree). |
| L179 | `reserved_ok = False` initial → `True` | equivalent | Overwritten whenever the payload parses; `usable` also requires `parsed is not None`. |
| L594, L597, L626, L655 | `ok = False` → `True` | verdict-equivalent | Short-circuit flags inside the environment and coverage checks; the failing code is already recorded, continuing only adds codes. |
| L672 | `counts.get(c, 0)` → `get(c, 1)` in the message `%d` | message-only | The condition is on the line above; this is the count printed in the message. |
| L673 | `partition_ok = False` → `True` | verdict-equivalent | The partition violation is already recorded; continuing runs coverage integrity too. |
| L742 | `ok = False` → `True` after a signatures defect | verdict-equivalent | `observation-records-malformed` already recorded; PAE bytes are still computable because payload/payloadType were valid in that branch. |
| L797 | `and` → `or` in the kind-check guard | equivalent | A record without a parsed payload has `parse_problem` set and no kind, so no new record reaches `_check_kind` with `parsed` unset; the problems it records on other records are read only through `parse_problem is None` / `usable` gates. |
| L807, L810 | `or` → `and` on `parse_problem` text | message-only | Selects which description is kept. |
| L1037 | `or` → `and` in a message | message-only | Fallback text of `referenced-record-unparseable`. |
| L1038, L1041, L1043 | `row_ok = False` → `True` | verdict-equivalent | The code is recorded before the flag; continuing runs class-match on the same row and adds codes. |
| L1048, L1070 | `unknown` list / `elif unknown` with `or` | diagnostic-only | Only changes when the auxiliary `row-resolves-unrecognised-kind` code is added beside `class-match-failed`. |
| L1091 (×4) | key ordering by `keyid` hint | equivalent | The hint only orders the attempts; every pinned key is tried. |

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
| L129 | `return False` → `True` in the defensive `except` | equivalent | No input reaches the handler (all decoding paths return `None`/`False` explicitly). |
| L144, L153 | `h[:32]` → `h[:33]` | equivalent | The extra byte sits above bit 255 and is cleared by the clamp that follows. |
| L145, L154 | `(1 << 254) - 8` → `(2 << 254) - 8` | equivalent | The two masks differ only in bit 254, which the next line sets to 1 unconditionally. |

### `cli.py` (2; lines of this tree)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L117 | `ensure_ascii=False` → `True` | equivalent | Produces an escaped but JSON-identical last line. |
| L152 | `or "-"` → `and "-"` | message-only | Human-readable accept line only. |

### Lines changed on 2026-11-20 (`tests/test_fix_20261120.py`) (3)

Measured on CPython 3.11.2 with the operators of `tests/mutate.py`, restricted to the lines that differ from
cbb79e5: `verifier.py` 27 sites, 25 killed; `cli.py` 5 sites, 4 killed.

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| verifier.py L1060 | `not in arming_postures` → `in` | equivalent | The list stays empty, `all()` over it is true; every arming and sealed record that is `kind_valid` already carries the pinned posture digest (`_check_kind`), so the comparison never decides (the reason the `all` → `any` survivor of this comparison had on cbb79e5, L948 there). A differential run of 400 generated statements (115 accepted) gave identical JSON lines and codes; the non-equivalent `==` → `!=` on L1063 differed on 146. |
| verifier.py L1063 | `all` → `any` on seal-vs-arming posture | equivalent | At most one distinct posture reaches the list (same reason); `any` and `all` agree on one element, and `bool(armings)` decides the empty case. Same differential: identical. |
| cli.py L45 | `o < 0x100` → `o <= 0x100` | equivalent | U+0100 is a letter (Lu): no character of Cc, Zl or Zp has code point 0x100 (the test over every code point passes on the mutant). |
