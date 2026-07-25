# DudeFS L1 — canonical bencode codec.
#
# IMPLEMENTATION.md §2 / ARCHITECTURE L1 / PROTOCOL §5 / FORMAL §1.
#
# Four types only: int, bytes, list, dict (byte-string keys, strictly sorted &
# unique). No floats, no bools, no str — bytes carry human-readable text by
# UTF-8 convention. Two iron properties this module must guarantee, because
# everything signed or PRF'd rests on them (FORMAL §1):
#
#   * injective  — length-prefixed throughout, so distinct values -> distinct bytes;
#   * canonical  — exactly one encoding per value (sorted keys, minimal ints),
#                  and the decoder *rejects* any non-canonical input rather than
#                  silently accepting it. Identity is the received bytes
#                  (ARCHITECTURE L1), so a lax decoder would let two byte strings
#                  denote one value and break content addressing.
#
# Grammar (all ASCII framing bytes):
#   int    : i <sign?> <digits> e          # minimal: no leading zeros, no -0
#   bytes  : <len> : <raw>                  # len minimal decimal
#   list   : l <item>* e
#   dict   : d (<bytes-key> <value>)* e     # keys strictly ascending, unique

from .errors import DudeFSError

# The four bencodable shapes (PEP 695 recursive type alias, native in 3.12).
# Documents intent; the encoder still validates dynamically and rejects
# anything else (bool, float, str, …).
#
# The sequence arm is `tuple`, not `list`: decoded wire data is immutable by
# nature (a tuple enforces that, and is lower-memory), and — because tuples are
# immutable they are *covariant*, so a `tuple[int, ...]` from `HLC.encode()`
# IS a `tuple[Bencodable, ...]`. That dissolves `list`'s construction-time
# invariance with no cast, while staying a concrete type so `isinstance(v,
# tuple)` in the `as_*` extractors narrows cleanly (unlike an abstract
# covariant `Sequence`, which would degrade to `tuple[Unknown, ...]`).
type Bencodable = int | bytes | tuple[Bencodable, ...] | dict[bytes, Bencodable]


class CodecError(DudeFSError):
    """The codec module's base error: any attempt to encode an unsupported
    value, or decode non-canonical / malformed input (incl. the `as_*`
    extractors — a decoded value that isn't the expected bencode shape)."""


# --------------------------------------------------------------------------- #
# Encoding                                                                     #
# --------------------------------------------------------------------------- #


def encode(value: object) -> bytes:
    out = bytearray()
    _encode_into(value, out)
    return bytes(out)


def _encode_into(value: object, out: bytearray) -> None:
    # bool is a subclass of int; reject it explicitly (DESIGN: use ints).
    if isinstance(value, bool):
        raise CodecError("bool is not encodable; use int 0/1")
    if isinstance(value, int):
        out += b"i"
        out += _int_ascii(value)
        out += b"e"
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        out += str(len(raw)).encode("ascii")
        out += b":"
        out += raw
    elif isinstance(value, (list, tuple)):
        out += b"l"
        for item in value:
            _encode_into(item, out)
        out += b"e"
    elif isinstance(value, dict):
        out += b"d"
        items = []
        for k, v in value.items():
            if isinstance(k, bool) or not isinstance(k, (bytes, bytearray)):
                raise CodecError("dict keys must be byte strings")
            items.append((bytes(k), v))
        items.sort(key=lambda kv: kv[0])
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CodecError("duplicate dict key")
        for k, v in items:
            out += str(len(k)).encode("ascii")
            out += b":"
            out += k
            _encode_into(v, out)
        out += b"e"
    else:
        raise CodecError(f"unencodable type: {type(value).__name__}")


def _int_ascii(n: int) -> bytes:
    # Python's str(int) is already minimal (no leading zeros, "-" only for
    # negatives, never "-0"), which is exactly the canonical form we want.
    return str(n).encode("ascii")


# --------------------------------------------------------------------------- #
# Decoding (canonical-only; rejects everything else)                          #
# --------------------------------------------------------------------------- #


def decode(data: bytes | bytearray) -> Bencodable:
    """Decode a complete bencoded value into the `Bencodable` union. Rejects
    trailing bytes and any non-canonical encoding. Callers narrow (via
    `isinstance` or the typed artifact `decode` methods) to recover concrete
    field types — the wire→typed boundary lives at the consumer, not here."""
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise CodecError("decode expects bytes")
    value, pos = _decode_at(data, 0)
    if pos != len(data):
        raise CodecError("trailing bytes after top-level value")
    return value


# --------------------------------------------------------------------------- #
# Typed extraction — the wire→typed boundary. Interpret a decoded `Bencodable`  #
# as a concrete shape or reject it. This is where malformed wire input is       #
# caught (a truncated/mistyped field fails here, not confusingly downstream).   #
# --------------------------------------------------------------------------- #


def as_int(v: Bencodable) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise CodecError(f"expected int, got {type(v).__name__}")
    return v


def as_bytes(v: Bencodable) -> bytes:
    if not isinstance(v, bytes):
        raise CodecError(f"expected bytes, got {type(v).__name__}")
    return v


def as_seq(v: Bencodable, length: int | None = None) -> tuple[Bencodable, ...]:
    """A bencode sequence (decoded as an immutable tuple). If `length` is given,
    the arity is checked too — a shape assertion, same family as as_int/as_bytes."""
    if not isinstance(v, tuple):
        raise CodecError(f"expected tuple, got {type(v).__name__}")
    if length is not None and len(v) != length:
        raise CodecError(f"expected a {length}-tuple, got length {len(v)}")
    return v


def as_dict(v: Bencodable) -> dict[bytes, Bencodable]:
    if not isinstance(v, dict):
        raise CodecError(f"expected dict, got {type(v).__name__}")
    return v


def field(d: Bencodable, key: bytes) -> Bencodable:
    """Fetch a required key from a decoded dict, or raise."""
    dd = as_dict(d)
    if key not in dd:
        raise CodecError(f"missing field {key!r}")
    return dd[key]


# Adversarial-input bounds. Both exist so a hostile frame is a TYPED, expected outcome at the
# decode boundary rather than an untyped crash in a serving thread (review K-9). Generous
# enough that no legitimate artifact approaches them.
_MAX_DEPTH = 64
_MAX_INT_DIGITS = 4096


def _decode_at(data: bytes, pos: int, depth: int = 0) -> tuple[Bencodable, int]:
    if pos >= len(data):
        raise CodecError("unexpected end of input")
    # Hostile input is EXPECTED input at this boundary (attackers send garbage), so it must
    # surface as a typed CodecError the caller can handle — never a bare RecursionError, which
    # is outside the DudeFSError tree and would crash a serving thread. `b"l" * 10**6` from an
    # UNAUTHENTICATED peer used to do exactly that, before any signature check (review K-9).
    if depth > _MAX_DEPTH:
        raise CodecError(f"nesting deeper than {_MAX_DEPTH}")
    tag = data[pos]
    if tag == 0x69:  # 'i'
        return _decode_int(data, pos)
    if tag == 0x6C:  # 'l'
        return _decode_list(data, pos, depth)
    if tag == 0x64:  # 'd'
        return _decode_dict(data, pos, depth)
    if 0x30 <= tag <= 0x39:  # digit -> byte string
        return _decode_bytes(data, pos)
    raise CodecError(f"invalid type tag {tag!r} at offset {pos}")


def _read_int_token(
    data: bytes, pos: int, terminator: int, *, allow_negative: bool
) -> tuple[int, int]:
    """Read a canonical decimal integer starting at pos, up to (not including)
    the first `terminator` byte. Enforces: at least one digit, no leading
    zeros, no '-0', '-' only when allowed."""
    neg = False
    if pos < len(data) and data[pos] == 0x2D:  # '-'
        if not allow_negative:
            raise CodecError("negative value not allowed here")
        neg = True
        pos += 1
    digit_start = pos
    while pos < len(data) and 0x30 <= data[pos] <= 0x39:
        pos += 1
    if pos == digit_start:
        raise CodecError("expected digits")
    digits = data[digit_start:pos]
    # Canonical form: no leading zeros; "0" is the only value starting with '0';
    # "-0" is forbidden.
    if len(digits) > 1 and digits[0] == 0x30:
        raise CodecError("non-canonical integer (leading zero)")
    if neg and digits == b"0":
        raise CodecError("non-canonical integer (negative zero)")
    if pos >= len(data) or data[pos] != terminator:
        raise CodecError("missing integer terminator")
    # CPython refuses int() above ~4300 digits with a bare ValueError — typed here, for the
    # same reason as the depth cap: a hostile literal is expected input, not a crash (K-9).
    if len(digits) > _MAX_INT_DIGITS:
        raise CodecError(f"integer literal longer than {_MAX_INT_DIGITS} digits")
    n = int(digits)
    if neg:
        n = -n
    return n, pos  # pos points at the terminator


def _decode_int(data: bytes, pos: int) -> tuple[int, int]:
    # data[pos] == 'i'
    n, end = _read_int_token(data, pos + 1, 0x65, allow_negative=True)  # 'e'
    return n, end + 1


def _decode_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    length, colon = _read_int_token(data, pos, 0x3A, allow_negative=False)  # ':'
    start = colon + 1
    end = start + length
    if end > len(data):
        raise CodecError("byte string longer than input")
    return data[start:end], end


def _decode_list(data: bytes, pos: int, depth: int = 0) -> tuple[tuple[Bencodable, ...], int]:
    # data[pos] == 'l' — decoded as an immutable tuple (see Bencodable).
    pos += 1
    items: list[Bencodable] = []
    while True:
        if pos >= len(data):
            raise CodecError("unterminated list")
        if data[pos] == 0x65:  # 'e'
            return tuple(items), pos + 1
        item, pos = _decode_at(data, pos, depth + 1)
        items.append(item)


def _decode_dict(data: bytes, pos: int, depth: int = 0) -> tuple[dict[bytes, Bencodable], int]:
    # data[pos] == 'd'
    pos += 1
    result: dict[bytes, Bencodable] = {}
    prev_key: bytes | None = None
    while True:
        if pos >= len(data):
            raise CodecError("unterminated dict")
        if data[pos] == 0x65:  # 'e'
            return result, pos + 1
        if not (0x30 <= data[pos] <= 0x39):
            raise CodecError("dict key must be a byte string")
        key, pos = _decode_bytes(data, pos)
        if prev_key is not None:
            if key == prev_key:
                raise CodecError("duplicate dict key")
            if key < prev_key:
                raise CodecError("non-canonical dict (keys out of order)")
        value, pos = _decode_at(data, pos)
        result[key] = value
        prev_key = key
