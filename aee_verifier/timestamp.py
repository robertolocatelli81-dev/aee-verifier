"""The ``issuedAt`` / ``armedAt`` timestamp profile.

Spec (``issuedAt``): the framework ``Timestamp`` type requires RFC 3339 in
UTC; this predicate pins the two open choices: the date-time separator and
the zone designator MUST be uppercase (``T``, ``Z``), and the zone MUST be
``Z``, ``+00:00`` or ``-00:00``.  Anything else is malformed.  ``armedAt``
carries the same profile.

RFC 3339 grammar: ``full-date "T" full-time`` with optional ``time-secfrac``
(``"." 1*DIGIT``).  ``time-second`` is ``00``-``60`` (leap seconds are part
of the RFC grammar and are therefore accepted syntactically).  The calendar
date must exist (month 1-12, day valid for that month and year).
"""

from __future__ import annotations

import re

# ASCII digits only ([0-9], not \d, which matches every Unicode decimal
# digit) and \Z, not $ (which also matches before a final "\n").
_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(Z|\+00:00|-00:00)\Z"
)

_DAYS = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def _leap(y: int) -> bool:
    return (y % 4 == 0 and y % 100 != 0) or y % 400 == 0


def parse_profile(value):
    """Return a comparable key for a valid timestamp, or None if the value
    is not a string in the profile.  Keys compare as instants (all UTC)."""
    if not isinstance(value, str):
        return None
    m = _RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    if not (1 <= mo <= 12):
        return None
    dim = _DAYS[mo] + (1 if (mo == 2 and _leap(y)) else 0)
    if not (1 <= d <= dim):
        return None
    if h > 23 or mi > 59 or s > 60:
        return None
    # pad fraction for lexicographic comparison; 30 digits covers any sane
    # producer and longer fractions still compare correctly after rstrip.
    frac = frac.rstrip("0")
    return (y, mo, d, h, mi, s, frac.ljust(64, "0"))


def is_valid(value) -> bool:
    return parse_profile(value) is not None


def not_later_than(a, b) -> bool:
    """True iff instant ``a`` <= instant ``b`` (both already parsed keys)."""
    return a <= b
