# Changelog

0.1.0 is the code of `main` at cbb79e5 (no tag was made of it). The sections of SPEC_NOTES named below give every
rule with the measure behind it.

## Unreleased

A secret given to the verifier does not come out of it (SPEC_NOTES N66, `tests/test_secrets_20261127.py`). Measured
on 0.2.0 (the PyPI wheel, whose package files are those of the tag): 6 of the 13 new tests fail there. A key set
where the `AEE_SUBSTRATE_KEYS` path goes, a key used as a member name, `keyid` or repeated name of the key policy,
and a value of a limit variable were written to stderr; a policy file that is not UTF-8 had one byte written. Now:

- warnings show a name or `keyid` of the key policy only when it is a string of at most 32 characters, otherwise its
  length (or the type of a value that is not a string);
- why the key policy could not be read is said by the exception's type, errno name, JSON line and column, never by
  its text; the path in `AEE_SUBSTRATE_KEYS` and the value of a limit variable only by their length;
- a key-policy entry carrying a private JWK member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`; RFC 7518 section
  6, RFC 8037 section 2) is skipped with a warning naming the member; in 0.2.0 it was kept. This is the only change of
  outcome: such an entry no longer pins its key.

Unchanged: verdicts, codes, exit statuses and the JSON line for every other input; a private key file where the
policy goes and secrets elsewhere in the environment came out nowhere on 0.2.0 either. The CI runs on every branch,
on Linux, macOS and Windows.

## 0.2.0 — released on 2026-11-22: outputs change

Verdicts, exit statuses and tiers change only in the cases listed here. The 225 tests of 0.1.0
(`tests/test_verifier.py` 163, `test_units.py` 27, `test_review_fixes.py` 26, `test_interop_20261114.py` 9, as they
were at cbb79e5) all pass on 0.2.0 (measured on CPython 3.11.2).

Changes of verdict, exit status or tier:

- an input longer than `AEE_MAX_INPUT_BYTES` (default 16 MiB) is unreadable input, exit 2 (N62); before, it was read
  whole;
- an input larger than the memory the process may use, at the read or later, is exit 2 with the JSON line (N61);
  before, a traceback and exit 1, the reject status;
- a limit variable that is not ASCII decimal digits of value at least 1 is exit 2, `usage` (N62);
- a substrate row is `unattested`, with a note, where the spec alone would say `attested`, when a record it cites
  carries more than `AEE_MAX_SIGNATURES_PER_RECORD` (default 16) signature entries whose `sig` is base64 of 64 bytes,
  or is left untried once the counted failed verifications reach `AEE_MAX_FAILED_VERIFICATIONS` (default 256) (N63);
- `Verifier(keys)` used as a library skips keys of small or mixed order, as the command line already did (N60): a
  row whose records only such a key verified is now `unattested`.

Packaging (new in 0.2.0): `pyproject.toml` (distribution `aee-verifier`, Python 3.9 or later, no dependency), the
console script `aee-verify`, so `python3 -m aee_verifier` works from any directory once installed; the workflows
`release-build.yml` (builds the wheel and sdist of a GitHub Release and runs the tests against the installed wheel) and
`pypi.yml` (uploads those files, checked against the release's `SHA256SUMS`, by PyPI Trusted Publishing).

Changes of the human-readable lines and of the library only (the JSON line does not move):

- line-breaking characters quoted from the statement are escaped (N61);
- notes name the members nothing reads inside the predicate, signature entries that verify nothing, and the predicate
  members L779-L781 reserves (N59);
- the refinement `attested-sealed` (N64): `Report.refined_tiers` and one note;
- the signatures of `moat-drop` and `uncommitted-observation` records are verified, as L1396 requires; one that does
  not verify is named (`Report.non_covering_unverified`, N65);
- repeated `observationRefs` indexes cost linear time, not quadratic (N23).
