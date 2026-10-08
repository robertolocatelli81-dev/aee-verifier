"""Strict I-JSON parser (RFC 7493 profile as pinned by the AEE predicate).

Written from the specification text alone.  The standard-library ``json``
module is deliberately not used because it accepts input the predicate
forbids: duplicate members (last wins), ``\\u`` escapes with a sign or
whitespace (``int(esc, 16)`` is permissive), unpaired surrogate escapes,
noncharacters, unbounded nesting and integers of any magnitude.

Rules enforced (spec "Prerequisites"):

* bytes MUST be valid UTF-8 with no overlong form and no encoded surrogate
  (Python's strict UTF-8 codec rejects both);
* a duplicate member anywhere, at any depth, is an error;
* a string literal MUST be a well-formed sequence of Unicode scalar values:
  no raw character below U+0020, ``\\u`` escapes of exactly four hex digits,
  a high-surrogate escape immediately followed by a low-surrogate escape,
  no unpaired surrogate of either half, no noncharacter (U+FDD0..U+FDEF,
  U+nFFFE, U+nFFFF) in member names or values;
* nesting depth (open arrays + objects, the outermost counting as 1) MUST
  NOT exceed 128;
* an integer (a number token with no fraction and no exponent) whose
  magnitude is at or above 2**53 is rejected (I-JSON safe-integer profile);
* numbers with a fraction or exponent are parsed as IEEE 754 doubles and
  rejected if they overflow to infinity.

Objects are returned as ``dict`` (insertion ordered), arrays as ``list``,
integers as ``int``, other numbers as ``float``.
"""

from __future__ import annotations

MAX_DEPTH = 128
SAFE_INT_LIMIT = 2 ** 53

_WS = " \t\n\r"
_HEX = "0123456789abcdefABCDEF"


class StrictJSONError(ValueError):
    """Raised with a short machine-usable ``kind`` and a human message."""

    def __init__(self, kind: str, message: str, pos: int = -1):
        super().__init__(message)
        self.kind = kind
        self.pos = pos


def is_noncharacter(cp: int) -> bool:
    return (0xFDD0 <= cp <= 0xFDEF) or (cp & 0xFFFE) == 0xFFFE


class _Parser:
    __slots__ = ("s", "i", "n", "depth")

    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.depth = 0

    # -- helpers -----------------------------------------------------------
    def _err(self, kind: str, msg: str) -> StrictJSONError:
        return StrictJSONError(kind, "%s at offset %d" % (msg, self.i), self.i)

    def _skip_ws(self) -> None:
        s, n = self.s, self.n
        i = self.i
        while i < n and s[i] in _WS:
            i += 1
        self.i = i

    def _peek(self) -> str:
        if self.i >= self.n:
            raise self._err("syntax", "unexpected end of input")
        return self.s[self.i]

    # -- grammar -----------------------------------------------------------
    def parse_document(self):
        self._skip_ws()
        value = self._parse_value()
        self._skip_ws()
        if self.i != self.n:
            raise self._err("syntax", "trailing content after JSON value")
        return value

    def _parse_value(self):
        c = self._peek()
        if c == "{":
            return self._parse_object()
        if c == "[":
            return self._parse_array()
        if c == '"':
            return self._parse_string()
        if c == "t":
            return self._parse_literal("true", True)
        if c == "f":
            return self._parse_literal("false", False)
        if c == "n":
            return self._parse_literal("null", None)
        if c == "-" or "0" <= c <= "9":
            return self._parse_number()
        raise self._err("syntax", "unexpected character %r" % c)

    def _parse_literal(self, word: str, value):
        if self.s.startswith(word, self.i):
            self.i += len(word)
            return value
        raise self._err("syntax", "invalid literal")

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise self._err("depth", "nesting depth exceeds %d" % MAX_DEPTH)

    def _parse_object(self) -> dict:
        self._enter()
        self.i += 1  # '{'
        out: dict = {}
        self._skip_ws()
        if self._peek() == "}":
            self.i += 1
            self.depth -= 1
            return out
        while True:
            self._skip_ws()
            if self._peek() != '"':
                raise self._err("syntax", "expected string member name")
            name = self._parse_string()
            self._skip_ws()
            if self._peek() != ":":
                raise self._err("syntax", "expected ':' after member name")
            self.i += 1
            self._skip_ws()
            value = self._parse_value()
            if name in out:
                raise self._err("duplicate", "duplicate member %r" % name)
            out[name] = value
            self._skip_ws()
            c = self._peek()
            if c == ",":
                self.i += 1
                continue
            if c == "}":
                self.i += 1
                self.depth -= 1
                return out
            raise self._err("syntax", "expected ',' or '}' in object")

    def _parse_array(self) -> list:
        self._enter()
        self.i += 1  # '['
        out: list = []
        self._skip_ws()
        if self._peek() == "]":
            self.i += 1
            self.depth -= 1
            return out
        while True:
            self._skip_ws()
            out.append(self._parse_value())
            self._skip_ws()
            c = self._peek()
            if c == ",":
                self.i += 1
                continue
            if c == "]":
                self.i += 1
                self.depth -= 1
                return out
            raise self._err("syntax", "expected ',' or ']' in array")

    def _parse_hex4(self) -> int:
        esc = self.s[self.i : self.i + 4]
        if len(esc) != 4 or any(ch not in _HEX for ch in esc):
            raise self._err("string", "\\u escape must have exactly four hex digits")
        self.i += 4
        return int(esc, 16)

    def _parse_string(self) -> str:
        s, n = self.s, self.n
        self.i += 1  # opening quote
        parts = []
        while True:
            if self.i >= n:
                raise self._err("syntax", "unterminated string")
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                self.i += 1
                if self.i >= n:
                    raise self._err("syntax", "unterminated escape")
                e = s[self.i]
                self.i += 1
                if e == "u":
                    cp = self._parse_hex4()
                    if 0xD800 <= cp <= 0xDBFF:
                        # high surrogate: MUST be immediately followed by \uDC00..\uDFFF
                        if s.startswith("\\u", self.i):
                            self.i += 2
                            lo = self._parse_hex4()
                            if not (0xDC00 <= lo <= 0xDFFF):
                                raise self._err("string", "high surrogate escape not followed by a low surrogate")
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        else:
                            raise self._err("string", "unpaired high surrogate escape")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        raise self._err("string", "unpaired low surrogate escape")
                    if is_noncharacter(cp):
                        raise self._err("string", "noncharacter U+%04X in string" % cp)
                    parts.append(chr(cp))
                elif e == '"':
                    parts.append('"')
                elif e == "\\":
                    parts.append("\\")
                elif e == "/":
                    parts.append("/")
                elif e == "b":
                    parts.append("\b")
                elif e == "f":
                    parts.append("\f")
                elif e == "n":
                    parts.append("\n")
                elif e == "r":
                    parts.append("\r")
                elif e == "t":
                    parts.append("\t")
                else:
                    raise self._err("string", "invalid escape \\%s" % e)
                continue
            cp = ord(c)
            if cp < 0x20:
                raise self._err("string", "raw control character U+%04X in string" % cp)
            if is_noncharacter(cp):
                raise self._err("string", "noncharacter U+%04X in string" % cp)
            parts.append(c)
            self.i += 1
        return "".join(parts)

    def _parse_number(self):
        s, n = self.s, self.n
        start = self.i
        i = start
        if s[i] == "-":
            i += 1
        if i >= n:
            raise self._err("syntax", "invalid number")
        if s[i] == "0":
            i += 1
        elif "1" <= s[i] <= "9":
            while i < n and "0" <= s[i] <= "9":
                i += 1
        else:
            raise self._err("syntax", "invalid number")
        is_int = True
        if i < n and s[i] == ".":
            is_int = False
            i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise self._err("syntax", "invalid number fraction")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        if i < n and s[i] in "eE":
            is_int = False
            i += 1
            if i < n and s[i] in "+-":
                i += 1
            if i >= n or not ("0" <= s[i] <= "9"):
                raise self._err("syntax", "invalid number exponent")
            while i < n and "0" <= s[i] <= "9":
                i += 1
        token = s[start:i]
        self.i = i
        if is_int:
            value = int(token)
            if abs(value) >= SAFE_INT_LIMIT:
                raise self._err("integer", "integer magnitude at or above 2**53")
            return value
        f = float(token)
        if f != f or f in (float("inf"), float("-inf")):
            raise self._err("number", "number out of IEEE 754 double range")
        return f


def decode_utf8_strict(data: bytes) -> str:
    """Decode raw bytes as UTF-8, rejecting overlong forms and CESU-8
    surrogates (Python's strict codec already does both)."""
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("utf8", "invalid UTF-8: %s" % exc, exc.start)


def loads_strict(data: bytes):
    """Parse ``data`` under the strict I-JSON profile.  Raises StrictJSONError."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("loads_strict expects bytes")
    text = decode_utf8_strict(bytes(data))
    return _Parser(text).parse_document()
