from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Self

from ..core import codec
from ..core.errors import DudeError


class AddressError(DudeError): ...


class Scheme(Enum):
    INPROC = b"inproc"

    UNIX = b"unix"
    TCP = b"tcp"
    ONION = b"onion"


@dataclass(frozen=True, slots=True)
class Address:
    scheme: Scheme
    value: str

    def encode(self) -> bytes:
        return self.scheme.value + b":" + self.value.encode()

    @classmethod
    def parse(cls, raw: bytes) -> Self:
        scheme, sep, value = raw.partition(b":")
        if not sep:
            raise AddressError(f"no scheme in address {raw!r}")
        try:
            return cls(Scheme(scheme), value.decode())
        except ValueError as e:
            raise AddressError(f"unknown scheme {scheme!r}") from e
        except UnicodeDecodeError as e:
            raise AddressError(f"address value is not utf-8: {value!r}") from e

    def __str__(self) -> str:
        return f"{self.scheme.value.decode()}:{self.value}"


def parse_all(raws: tuple[bytes, ...]) -> tuple[Address, ...]:
    out: list[Address] = []
    for raw in raws:
        try:
            out.append(Address.parse(raw))
        except AddressError:
            continue
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Endpoint:
    address: Address
    options: Mapping[bytes, bytes] = field(default_factory=dict)

    def encode(self) -> bytes:
        return codec.encode([self.address.encode(), dict(sorted(self.options.items()))])

    @classmethod
    def parse(cls, raw: bytes) -> Endpoint:
        try:
            decoded = codec.decode(raw)
        except codec.CodecError:
            return cls(Address.parse(raw))
        if isinstance(decoded, bytes):
            return cls(Address.parse(decoded))
        f = codec.as_seq(decoded, 2)
        opts = codec.as_dict(f[1])
        parsed = {k: codec.as_bytes(v) for k, v in opts.items()}
        return cls(Address.parse(codec.as_bytes(f[0])), parsed)

    def option(self, key: bytes, default: bytes = b"") -> bytes:
        return self.options.get(key, default)


def endpoints(raws: tuple[bytes, ...]) -> tuple[Endpoint, ...]:
    out: list[Endpoint] = []
    for raw in raws:
        try:
            out.append(Endpoint.parse(raw))
        except (AddressError, codec.CodecError):
            continue
    return tuple(out)
