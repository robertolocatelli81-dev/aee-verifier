"""Ed25519 signature verification (RFC 8032 section 5.1), standard library only.

The predicate's consumer policy example names Ed25519 public-key bytes as
the substrate observation keys, and the harness hands keys over as
``publicKeyHex``; a 32-byte key is treated as a raw Ed25519 public key.

Only verification is implemented here (a verifier never signs).  The group
equation checked is the cofactorless ``[S]B = R + [k]A``, which RFC 8032
states is sufficient.  Performance is irrelevant at the scale of a single
statement (a few signatures), so the arithmetic is plain Python integers
on extended twisted-Edwards coordinates.
"""

from __future__ import annotations

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
# sqrt(-1) mod p
I = pow(2, (P - 1) // 4, P)

# Base point B (affine), from RFC 8032 section 5.1
_BY = (4 * pow(5, P - 2, P)) % P


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
# Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z
_B = (_BX, _BY, 1, _BX * _BY % P)
_NEUTRAL = (0, 1, 1, 0)


def _add(p, q):
    X1, Y1, Z1, T1 = p
    X2, Y2, Z2, T2 = q
    A = (Y1 - X1) * (Y2 - X2) % P
    Bv = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * T1 * T2 * D % P
    Dv = 2 * Z1 * Z2 % P
    E = Bv - A
    F = Dv - C
    G = Dv + C
    H = Bv + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s: int, p):
    q = _NEUTRAL
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _decode_point(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _equal(p, q) -> bool:
    X1, Y1, Z1, _ = p
    X2, Y2, Z2, _ = q
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature of
    ``message`` under ``public_key``.  Never raises on malformed input."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        A = _decode_point(public_key)
        if A is None:
            return False
        R = _decode_point(signature[:32])
        if R is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        h = hashlib.sha512(signature[:32] + public_key + message).digest()
        k = int.from_bytes(h, "little") % L
        lhs = _mul(s, _B)
        rhs = _add(R, _mul(k, A))
        return _equal(lhs, rhs)
    except Exception:  # defensive: a verifier must never crash on input
        return False


# --- helpers kept here so tests can produce signatures without a dependency ---

def _encode_point(p) -> bytes:
    X, Y, Z, _ = p
    zi = pow(Z, P - 2, P)
    x = X * zi % P
    y = Y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_key_from_seed(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encode_point(_mul(a, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    """RFC 8032 5.1.6 signing.  Used by the test-suite only."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    A = _encode_point(_mul(a, _B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    Rb = _encode_point(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(Rb + A + message).digest(), "little") % L
    s = (r + k * a) % L
    return Rb + s.to_bytes(32, "little")
