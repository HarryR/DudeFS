import dataclasses
import json
from collections.abc import Callable
from enum import Enum, StrEnum

import dacite

from ..net.address import Address, Scheme
from . import crypto
from .units import Millis


def json_safe(obj):
    if isinstance(obj, Enum):
        v = obj.value
        return v.decode() if isinstance(v, bytes) else v
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_safe(v) for v in obj]
    return obj


def dumps(obj) -> str:
    return json.dumps(json_safe(dataclasses.asdict(obj)))


def dump(obj) -> bytes:
    return dumps(obj).encode()


_HOOKS: dict[type, Callable] = {
    Millis: Millis,
    crypto.PublicKey: lambda v: crypto.PublicKey(bytes.fromhex(v)),
    crypto.Digest: lambda v: crypto.Digest(bytes.fromhex(v)),
    Address: lambda v: Address.parse(v.encode()) if isinstance(v, str) else v,
    Scheme: lambda v: Scheme(v.encode() if isinstance(v, str) else v),
}

_CONFIG = dacite.Config(type_hooks=_HOOKS, cast=[tuple, StrEnum])


def load[T](cls: type[T], raw: bytes) -> T:
    return dacite.from_dict(cls, json.loads(raw), config=_CONFIG)
