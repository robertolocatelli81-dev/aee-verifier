# Mutation testing — positive control of the test-suite

`tests/mutate.py` mutates the sources one site at a time (drop a
`rep.fail(...)` / `problems.append(...)`, flip a comparison, `and`/`or`,
drop a `not`, swap `any`/`all`, bump a small constant, flip a boolean) and
runs the whole suite (`tests/test_verifier.py` + `tests/test_units.py`) in an
isolated copy of the repository.  A mutant that passes the suite has
survived.  Measured 2026-10-08 UTC, CPython 3.11.2, 8 jobs.

| Module | Sites | Killed | Survived |
|--------|------:|-------:|---------:|
| `verifier.py` | 531 | 504 | 27 |
| `strict_json.py` | 122 | 121 | 1 |
| `jcs.py` | 47 | 42 | 5 |
| `timestamp.py` | 49 | 47 | 2 |
| `ed25519.py` | 77 | 70 | 7 |
| `cli.py` | 20 | 18 | 2 |
| **Total** | **846** | **802** | **44** |

Earlier rounds found real holes, since closed by added tests: `all`→`any`
on mixed-validity arrays (expectedPayloads, aeePayloadCommitment, signatures,
`is_bmp`), DSSE-envelope input defects, environment members missing on
artifact-only statements, the method cap with two interception records, a
manifest class disclosed nowhere with otherwise consistent rows,
`caught == labels`, depth accounting after a closed sibling container, U+0020
escaped by JCS, 30 February in a leap year, Ed25519 non-canonical point
encodings and `_equal` with `or`.

## Survivors, classified

Line numbers refer to the committed sources.

### `verifier.py` (27)

| Line | Mutation | Class | Why it survives |
|------|----------|-------|-----------------|
| L71 | `<=` → `<` in `is_bmp` | equivalent | U+FFFF is a noncharacter, already rejected by the parser; no string reaching `is_bmp` contains it. |
| L97 | `validate=True` → `False` | equivalent | The alphabet is checked by regex before `b64decode`; `validate` has nothing left to reject. |
| L139 | `reserved_ok = False` initial → `True` | equivalent | Overwritten whenever the payload parses; `usable` also requires `parsed is not None`. |
| L357 | `all` → `any` over row attackId types | verdict-equivalent | Only runs the set comparison on rows already flagged `row-attack-id-malformed`; adds a code, never flips a verdict. |
| L488, L491, L515, L520, L548 | `ok = False` → `True` | verdict-equivalent | Short-circuit flags inside the environment checks; the failing code is already recorded, continuing only adds codes. |
| L565 | `counts.get(c, 0)` → `get(c, 1)` in the message `%d` | message-only | The condition is on L564; this is the count printed in the message. |
| L566 | `partition_ok = False` → `True` | verdict-equivalent | The partition violation is already recorded; continuing runs coverage integrity too. |
| L635 | `ok = False` → `True` after a signatures defect | verdict-equivalent | `observation-records-malformed` already recorded; PAE bytes are still computable because payload/payloadType were valid in that branch. |
| L670 | `usable and covering_kind` → `or` | equivalent | `_check_kind` on an unusable or non-covering record appends problems to a record no later step reads as valid. |
| L680, L683 | `or` → `and` on `parse_problem` text | message-only | Selects which description is kept. |
| L797 | `and` → `or` in `resolved()` range filter | equivalent | Out-of-range references set `refs` to `None` earlier, so every index reaching here is in range. |
| L887 | `or` → `and` in a message | message-only | Fallback text of `referenced-record-unparseable`. |
| L888, L891, L893 | `row_ok = False` → `True` | verdict-equivalent | The code is recorded before the flag; continuing runs class-match on the same row and adds codes. |
| L898, L915 | `unknown` list / `elif unknown` with `or` | diagnostic-only | Only changes when the auxiliary `row-resolves-unrecognised-kind` code is added beside `class-match-failed`. |
| L908 | `all` → `any` on seal-vs-arming posture | equivalent | Every bound arming record must already equal the pinned digest (universal check), so all resolved armings share one posture. |
| L936 (×4) | key ordering by `keyid` hint | equivalent | The hint only orders the attempts; every pinned key is tried. |

### `strict_json.py` (1)

| L42 | `pos: int = -1` default → `-2` | equivalent | Default never read for behaviour. |

### `jcs.py` (5)

| L94, L95 | `x < 0` → `<=` | equivalent | `x == 0` returns `"0"` on L92 before either line. |
| L101 | `-6 < n <= 0` → `<= 1` | equivalent | `n == 1` is taken by the `0 < n <= 21` branch above. |
| L105 (×2) | `e >= 0` → `e > 0`; `0` → `1` | equivalent | Exponent form is only reached with `n > 21` or `n <= -6`, so `e = n - 1` is never 0. |

### `timestamp.py` (2)

| L23 | `_DAYS[0] = 0` → `1` | equivalent | Index 0 is never used (`1 <= mo <= 12` checked first). |
| L50 | pad width `64` → `65` | equivalent | Both operands of every comparison are padded identically. |

### `ed25519.py` (7)

| L36 | `(P + 3) // 8` → `(P + 4) // 8` | equivalent | `P + 3 ≡ 0 (mod 8)`, so the floor division yields the same exponent. |
| L107 | `s >= L` → `s > L` | equivalent in practice | Admits the single value `s = L`, the non-canonical twin of `s = 0`; a verifying signature with `s = 0` requires `R = -[k]A` where `k` depends on `R`, which no test or realistic input constructs. Listed rather than hidden. |
| L115 | `return False` → `True` in the defensive `except` | equivalent | No input reaches the handler (all decoding paths return `None`/`False` explicitly). |
| L130, L139 | `h[:32]` → `h[:33]` | equivalent | The extra byte sits above bit 255 and is cleared by the clamp that follows. |
| L131, L140 | `(1 << 254) - 8` → `(2 << 254) - 8` | equivalent | The two masks differ only in bit 254, which the next line sets to 1 unconditionally. |

### `cli.py` (2)

| L68 | `ensure_ascii=False` → `True` | equivalent | Produces an escaped but JSON-identical last line. |
| L92 | `or "-"` → `and "-"` | message-only | Human-readable accept line only. |
