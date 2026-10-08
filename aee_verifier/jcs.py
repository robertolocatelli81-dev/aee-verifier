"""RFC 8785 (JSON Canonicalization Scheme) serializer.

Input is the Python value tree produced by ``strict_json`` (dict / list /
str / int / float / bool / None).  Output is the canonical UTF-8 bytes.

* object members are sorted by UTF-16 code units (RFC 8785 section 3.2.3);
  comparing the UTF-16BE byte encoding of each name gives exactly that order,
  including the "shorter prefix first" rule;
* strings follow section 3.2.2.2: ``\\b \\t \\n \\f \\r`` short escapes,
  other controls as lowercase ``\\u00xx``, ``"`` and ``\\`` escaped,
  everything else emitted as-is;
* numbers follow ECMAScript Number::toString (section 3.2.2.3), implemented
  on top of Python's shortest round-trip ``repr``; integers print as plain
  decimal digits.  NaN and infinities raise.
"""

from __future__ import annotations

import math


class JCSError(ValueError):
    pass


def utf16_key(s: str) -> bytes:
    """Sort key giving RFC 8785 (UTF-16 code unit) order for ``str``."""
    return s.encode("utf-16-be", "surrogatepass")


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20:
            if ch == "\b":
                out.append("\\b")
            elif ch == "\t":
                out.append("\\t")
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\f":
                out.append("\\f")
            elif ch == "\r":
                out.append("\\r")
            else:
                out.append("\\u%04x" % cp)
        elif 0xD800 <= cp <= 0xDFFF:
            raise JCSError("lone surrogate U+%04X cannot be canonicalized" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _shortest_digits(x: float):
    """Return (digits, n) with x == 0.d1d2..dk * 10**n, digits shortest
    round-trip, no leading or trailing zeros.  x must be finite, > 0."""
    r = repr(x)
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = ip + fp
    n = len(ip) + exp
    # strip leading zeros (each one shifts the decimal point left)
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    if not digits:
        raise JCSError("zero reached _shortest_digits")
    return digits, n


def format_number(x) -> str:
    """ECMAScript Number::toString for a finite double."""
    if isinstance(x, bool):
        raise JCSError("bool is not a number")
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        raise JCSError("NaN and Infinity are not permitted")
    if x == 0:
        return "0"  # covers -0.0 as well
    sign = "-" if x < 0 else ""
    digits, n = _shortest_digits(-x if x < 0 else x)
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        if k == 1:
            body = digits + "e" + esign + str(abs(e))
        else:
            body = digits[0] + "." + digits[1:] + "e" + esign + str(abs(e))
    return sign + body


def _serialize(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_escape_string(value))
    elif isinstance(value, (int, float)):
        out.append(format_number(value))
    elif isinstance(value, list):
        out.append("[")
        first = True
        for item in value:
            if not first:
                out.append(",")
            first = False
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        first = True
        if not all(isinstance(k, str) for k in value):
            raise JCSError("object member names must be strings")
        for name in sorted(value.keys(), key=utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_escape_string(name))
            out.append(":")
            _serialize(value[name], out)
        out.append("}")
    else:
        raise JCSError("unsupported value type %s" % type(value).__name__)


def canonicalize(value) -> bytes:
    out: list = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")
