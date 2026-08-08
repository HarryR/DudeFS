from .errors import DudeError

type Bencodable = int | bytes | tuple[Bencodable, ...] | dict[bytes, Bencodable]


class CodecError(DudeError): ...


def encode(value: object) -> bytes:
    out = bytearray()
    _encode_into(value, out)
    return bytes(out)


def _encode_into(value: object, out: bytearray) -> None:  # noqa: C901
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
    return str(n).encode("ascii")


def decode(data: bytes | bytearray) -> Bencodable:
    if isinstance(data, bytearray):
        data = bytes(data)
    value, pos = _decode_at(data, 0)
    if pos != len(data):
        raise CodecError("trailing bytes after top-level value")
    return value


def as_int(v: Bencodable) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise CodecError(f"expected int, got {type(v).__name__}")
    return v


def as_bytes(v: Bencodable) -> bytes:
    if not isinstance(v, bytes):
        raise CodecError(f"expected bytes, got {type(v).__name__}")
    return v


def as_seq(v: Bencodable, length: int | None = None) -> tuple[Bencodable, ...]:
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
    dd = as_dict(d)
    if key not in dd:
        raise CodecError(f"missing field {key!r}")
    return dd[key]


_MAX_DEPTH = 64
_MAX_INT_DIGITS = 4096


def _decode_at(data: bytes, pos: int, depth: int = 0) -> tuple[Bencodable, int]:
    if pos >= len(data):
        raise CodecError("unexpected end of input")
    if depth > _MAX_DEPTH:
        raise CodecError(f"nesting deeper than {_MAX_DEPTH}")
    tag = data[pos]
    if tag == 0x69:
        return _decode_int(data, pos)
    if tag == 0x6C:
        return _decode_list(data, pos, depth)
    if tag == 0x64:
        return _decode_dict(data, pos, depth)
    if 0x30 <= tag <= 0x39:
        return _decode_bytes(data, pos)
    raise CodecError(f"invalid type tag {tag!r} at offset {pos}")


def _read_int_token(
    data: bytes, pos: int, terminator: int, *, allow_negative: bool
) -> tuple[int, int]:
    neg = False
    if pos < len(data) and data[pos] == 0x2D:
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
    if len(digits) > 1 and digits[0] == 0x30:
        raise CodecError("non-canonical integer (leading zero)")
    if neg and digits == b"0":
        raise CodecError("non-canonical integer (negative zero)")
    if pos >= len(data) or data[pos] != terminator:
        raise CodecError("missing integer terminator")
    if len(digits) > _MAX_INT_DIGITS:
        raise CodecError(f"integer literal longer than {_MAX_INT_DIGITS} digits")
    n = int(digits)
    if neg:
        n = -n
    return n, pos


def _decode_int(data: bytes, pos: int) -> tuple[int, int]:
    n, end = _read_int_token(data, pos + 1, 0x65, allow_negative=True)
    return n, end + 1


def _decode_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    length, colon = _read_int_token(data, pos, 0x3A, allow_negative=False)
    start = colon + 1
    end = start + length
    if end > len(data):
        raise CodecError("byte string longer than input")
    return data[start:end], end


def _decode_list(data: bytes, pos: int, depth: int = 0) -> tuple[tuple[Bencodable, ...], int]:
    pos += 1
    items: list[Bencodable] = []
    while True:
        if pos >= len(data):
            raise CodecError("unterminated list")
        if data[pos] == 0x65:
            return tuple(items), pos + 1
        item, pos = _decode_at(data, pos, depth + 1)
        items.append(item)


def _decode_dict(data: bytes, pos: int, depth: int = 0) -> tuple[dict[bytes, Bencodable], int]:
    pos += 1
    result: dict[bytes, Bencodable] = {}
    prev_key: bytes | None = None
    while True:
        if pos >= len(data):
            raise CodecError("unterminated dict")
        if data[pos] == 0x65:
            return result, pos + 1
        if not (0x30 <= data[pos] <= 0x39):
            raise CodecError("dict key must be a byte string")
        key, pos = _decode_bytes(data, pos)
        if prev_key is not None:
            if key == prev_key:
                raise CodecError("duplicate dict key")
            if key < prev_key:
                raise CodecError("non-canonical dict (keys out of order)")
        value, pos = _decode_at(data, pos, depth + 1)
        result[key] = value
        prev_key = key
