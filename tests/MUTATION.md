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
others were not run again. Then the decisions of the same day (`tests/test_decisions_20261120.py`, SPEC_NOTES N62-N64)
changed `verifier.py` and `cli.py` again: on this tree `tests/mutate.py` finds 620 sites in `verifier.py` and 46 in
`cli.py` (973 in the six modules), and the sites on the lines they changed were run (last section: 45 and 15; then
SPEC_NOTES N65, the signatures of the records that cover nothing: 3 sites, 3 killed; then, on 2026-11-21, the limit
variables read 4000 digits at a time in `cli.py`: 7 sites on the changed lines, 7 killed; then, the same day, the
counting rule of N63 (the failed attempts of a record that verifies are not counted, the limit checked before a
record): 7 sites on the changed lines of `verifier.py`, 6 killed by the suite of that change and the seventh, an
untried record cached as verified, by a test then added: 7 killed; then, the same day, the second form of that rule
(the entries that verify nothing are counted also on a record that verifies, but for one): 3 sites on the changed lines
of `verifier.py`, 3 killed; then, for 0.2.0, the counts in the note of that limit: 4 sites on the changed lines of
`verifier.py`, 4 killed).
The survivor lines of `verifier.py` and `cli.py` below are renumbered to this tree
(same code, moved lines; renumbered with a line-by-line match of the sources of 64227ea and of this tree). The four
survivors of cbb79e5 at L1091 of 64227ea (key ordering by the `keyid` hint, equivalent then) are gone: that loop was rewritten by
N63 and its new sites are run in the last section. Two more rows of cbb79e5 are gone: L833 (`and` → `or` in the `resolved()` range filter: the
line was rewritten and its mutant is now killed) and L948 (`all` → `any` on seal-vs-arming posture: rewritten, now
L1117 in the section of `tests/test_fix_20261120.py`).
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

### `verifier.py` (19 of the 25 of cbb79e5; lines of this tree)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L140 | `<=` → `<` in `is_bmp` | equivalent | U+FFFF is a noncharacter, already rejected by the parser; no string reaching `is_bmp` contains it. |
| L166 | `validate=True` → `False` | equivalent | The regexes above it are anchored with `\Z` and admit only the alphabet plus up to two `=`; `validate` has nothing left to reject (490,000 sampled strings agree). |
| L208 | `reserved_ok = False` initial → `True` | equivalent | Overwritten whenever the payload parses; `usable` also requires `parsed is not None`. |
| L647, L650, L679, L708 | `ok = False` → `True` | verdict-equivalent | Short-circuit flags inside the environment and coverage checks; the failing code is already recorded, continuing only adds codes. |
| L725 | `counts.get(c, 0)` → `get(c, 1)` in the message `%d` | message-only | The condition is on the line above; this is the count printed in the message. |
| L726 | `partition_ok = False` → `True` | verdict-equivalent | The partition violation is already recorded; continuing runs coverage integrity too. |
| L795 | `ok = False` → `True` after a signatures defect | verdict-equivalent | `observation-records-malformed` already recorded; PAE bytes are still computable because payload/payloadType were valid in that branch. |
| L850 | `and` → `or` in the kind-check guard | equivalent | A record without a parsed payload has `parse_problem` set and no kind, so no new record reaches `_check_kind` with `parsed` unset; the problems it records on other records are read only through `parse_problem is None` / `usable` gates. |
| L860, L863 | `or` → `and` on `parse_problem` text | message-only | Selects which description is kept. |
| L1091 | `or` → `and` in a message | message-only | Fallback text of `referenced-record-unparseable`. |
| L1092, L1095, L1097 | `row_ok = False` → `True` | verdict-equivalent | The code is recorded before the flag; continuing runs class-match on the same row and adds codes. |
| L1102, L1124 | `unknown` list / `elif unknown` with `or` | diagnostic-only | Only changes when the auxiliary `row-resolves-unrecognised-kind` code is added beside `class-match-failed`. |

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
| L162 | `ensure_ascii=False` → `True` | equivalent | Produces an escaped but JSON-identical last line. |
| L205 | `or "-"` → `and "-"` | message-only | Human-readable accept line only. |

### Lines changed on 2026-11-20 (`tests/test_fix_20261120.py`) (3)

Measured on CPython 3.11.2 with the operators of `tests/mutate.py`, restricted to the lines that differ from
cbb79e5: `verifier.py` 27 sites, 25 killed; `cli.py` 5 sites, 4 killed.

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| verifier.py L1114 | `not in arming_postures` → `in` | equivalent | The list stays empty, `all()` over it is true; every arming and sealed record that is `kind_valid` already carries the pinned posture digest (`_check_kind`), so the comparison never decides (the reason the `all` → `any` survivor of this comparison had on cbb79e5, L948 there). A differential run of 400 generated statements (115 accepted) gave identical JSON lines and codes; the non-equivalent `==` → `!=` on L1117 differed on 146. |
| verifier.py L1117 | `all` → `any` on seal-vs-arming posture | equivalent | At most one distinct posture reaches the list (same reason); `any` and `all` agree on one element, and `bool(armings)` decides the empty case. Same differential: identical. |
| cli.py L90 | `o < 0x100` → `o <= 0x100` | equivalent | U+0100 is a letter (Lu): no character of Cc, Zl or Zp has code point 0x100 (the test over every code point passes on the mutant). |

### Lines changed by the decisions of 2026-11-20 (`tests/test_decisions_20261120.py`) (4)

Measured on CPython 3.11.2 (`nice -n 19`, one job) with the operators of `tests/mutate.py`, restricted to the lines
that differ from 64227ea: `verifier.py` 45 sites, 39 killed by the suite of the first run; of the 6 survivors, 5 were
killed by three tests then added (`test_each_key_is_tried_once_per_entry`,
`test_entries_hinting_a_pinned_keyid_are_tried_first`, `test_one_verifying_seal_is_enough`; re-run with the whole
suite): 44 killed, 1 survived. `cli.py` 15 sites, 12 killed, 3 survived. The 4 survivors are equivalent, shown three ways
each: reading, the outcome below, and a differential run against the unmutated code
(`equiv_mutanti.py` in the measurement folder of 2026-11-20): 0 differences, while the non-equivalent mutants used as
positive controls differ (`verifier.py` L1164 `t[0]` → `t[1]`: 48 of 150 statements; `cli.py` L74 `>` → `>=`: 7 of
96 cases).

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| verifier.py L1160 | sort key `1` → `2` for an entry whose `keyid` names no pinned key | equivalent | The key only orders the entries, pinned hints (`0`) first; `0 < 2` orders them as `0 < 1` does. Differential: 150 generated statements, identical JSON line, refinement, notes and number of verifications. |
| cli.py L40 | `1 << 20` → `2 << 20`, `1 << 20` → `1 << 21` (read chunk) | equivalent | The chunk only sets how much one `read` asks for; each read is also capped at `limit + 1 - total`, so the bytes read and the moment `InputTooLarge` is raised do not depend on it. Differential: 96 file sizes x limits around 1 and 2 MiB, identical results. |
| cli.py L69 | `limit + 1 - total` → `limit + 2 - total` | equivalent | One byte more may be read before `total > limit` raises; the file is refused exactly when it is longer than the limit either way. Same differential: identical. |
