# Ed25519 — pure-Python RFC 8032 reference implementation (vendored).
#
# ==========================================================================
#  POC-ONLY.  This is NOT constant-time and performs no side-channel
#  hardening. It exists so the DudeFS proof of concept can sign and verify
#  with zero pip dependencies (IMPLEMENTATION.md §1). Before any production
#  or real-confidentiality claim, replace with a vetted library (libsodium /
#  cryptography). ~1 ms per operation is fine at the POC's 1-3 clients, n<=7.
# ==========================================================================
#
# Derived from the RFC 8032 §6 reference pseudocode (public domain). SHA-512
# comes from the standard library. Exposes the minimal surface the L0 Signer
# needs: keypair derivation, detached sign, and verify.

from __future__ import annotations

import hashlib

# A curve point in extended homogeneous coordinates (X, Y, Z, T).
type Point = tuple[int, int, int, int]

# Curve / field constants (RFC 8032 §5.1).
_b = 256
_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493  # group order
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)  # sqrt(-1)


def _sha512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _sha512_int(m: bytes) -> int:
    return int.from_bytes(_sha512(m), "little")


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


# Base point B (RFC 8032 §5.1). Extended coordinates (X, Y, Z, T).
def _recover_x(y: int, sign: int) -> int | None:
    if y >= _p:
        return None
    y2 = (y * y) % _p
    u = (y2 - 1) % _p
    v = (_d * y2 + 1) % _p
    # x = u * v^3 * (u * v^7)^((p-5)/8)
    v3 = (v * v * v) % _p
    v7 = (v3 * v3 * v) % _p
    x = (u * v3 * pow(u * v7 % _p, (_p - 5) // 8, _p)) % _p
    vx2 = (v * x * x) % _p
    if vx2 == u:  # x^2 = u/v
        pass
    elif vx2 == (-u) % _p:
        x = (x * _I) % _p
    else:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = _p - x
    return x


_By = (4 * _inv(5)) % _p
_Bx = _recover_x(_By, 0)
assert _Bx is not None  # the base-point y always recovers a valid x
# Extended homogeneous coordinates: (X, Y, Z, T) with x=X/Z, y=Y/Z, xy=T/Z.
_B: Point = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)
_IDENTITY: Point = (0, 1, 1, 0)


def _point_add(P: Point, Q: Point) -> Point:
    # RFC 8032 §5.1.4 — unified addition on the twisted Edwards curve.
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _p
    b = ((y1 + x1) * (y2 + x2)) % _p
    c = (t1 * 2 * _d * t2) % _p
    dd = (z1 * 2 * z2) % _p
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = (e * f) % _p
    y3 = (g * h) % _p
    t3 = (e * h) % _p
    z3 = (f * g) % _p
    return (x3, y3, z3, t3)


def _scalarmult(P: Point, e: int) -> Point:
    result = _IDENTITY
    while e > 0:
        if e & 1:
            result = _point_add(result, P)
        P = _point_add(P, P)
        e >>= 1
    return result


def _encode_point(P: Point) -> bytes:
    x, y, z, _t = P
    zinv = _inv(z)
    x = (x * zinv) % _p
    y = (y * zinv) % _p
    val = y | ((x & 1) << 255)
    return val.to_bytes(32, "little")


def _decode_point(s: bytes) -> Point | None:
    if len(s) != 32:
        return None
    val = int.from_bytes(s, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _p)


def _clamp(h32: bytes) -> int:
    a = int.from_bytes(h32, "little")
    a &= (1 << 254) - 8  # clear low 3 bits, clear bit 255
    a |= 1 << 254  # set bit 254
    return a


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


def publickey(sk: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed (secret key)."""
    if len(sk) != 32:
        raise ValueError("ed25519 secret key must be 32 bytes")
    h = _sha512(sk)
    a = _clamp(h[:32])
    A = _scalarmult(_B, a)
    return _encode_point(A)


def sign(sk: bytes, msg: bytes) -> bytes:
    """Detached 64-byte signature over msg under seed sk (RFC 8032)."""
    if len(sk) != 32:
        raise ValueError("ed25519 secret key must be 32 bytes")
    h = _sha512(sk)
    a = _clamp(h[:32])
    prefix = h[32:]
    A = _encode_point(_scalarmult(_B, a))
    r = _sha512_int(prefix + msg) % _L
    R = _scalarmult(_B, r)
    Renc = _encode_point(R)
    k = _sha512_int(Renc + A + msg) % _L
    S = (r + k * a) % _L
    return Renc + S.to_bytes(32, "little")


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a 64-byte detached signature. Returns True/False; never raises
    on well-formed-length inputs."""
    if len(sig) != 64 or len(pk) != 32:
        return False
    Renc = sig[:32]
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    A = _decode_point(pk)
    R = _decode_point(Renc)
    if A is None or R is None:
        return False
    k = _sha512_int(Renc + pk + msg) % _L
    # Check [S]B == R + [k]A
    lhs = _scalarmult(_B, S)
    rhs = _point_add(R, _scalarmult(A, k))
    return _point_equal(lhs, rhs)


def _point_equal(P: Point, Q: Point) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    # x1/z1 == x2/z2  and  y1/z1 == y2/z2
    if (x1 * z2 - x2 * z1) % _p != 0:
        return False
    if (y1 * z2 - y2 * z1) % _p != 0:
        return False
    return True
