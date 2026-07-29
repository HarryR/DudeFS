# dude.net.address — where a peer can be reached. See ../../TRANSPORT.md.
#
# The management store records addresses as opaque `bytes` and this module is the ONLY thing that
# parses them (#transport-adds-no-trust: transport adds no trust, and carrier vocabulary must not
# leak into the
# log). So `store.management` can hold a locator for a carrier it has never heard of, and the log
# stays free of transport concepts.
#
# AN ADDRESS IS NOT AN IDENTITY. A peer IS its public key; an address is merely one place that key
# might currently be answering. Multi-homing is therefore the normal case rather than a feature: a
# node has several addresses, they change, and none of them authenticates anything. Every security
# property comes from the envelope inside.

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Self

from ..core import codec
from ..core.errors import DudeError


class AddressError(DudeError):
    """A locator that is malformed or names a carrier we do not have."""


class Scheme(Enum):
    """Carriers we can dial. Closed, for the same reasons `Verb` is: a Rust or Go port matches
    exhaustively, and "what can this node reach?" has an enumerable answer.

    Adding a carrier is a code change in a transport-selection table, which is honest — the code
    genuinely cannot dial a scheme it has no implementation for, so an open string would just move
    the failure from parse time to dial time."""

    INPROC = b"inproc"
    """No I/O at all: delivery by direct call, for tests and single-process clusters. Exists so the
    whole protocol can be driven with no sockets, which is the same reason `Mailbox` is sans-I/O."""

    UNIX = b"unix"
    TCP = b"tcp"


# Dial preference: cheapest and most local first. A node reachable both in-process and over TCP
# should not be dialled over TCP, and sorting by the scheme NAME would have done exactly that
# (b"tcp" < b"unix"). Stability alone is not enough — the order has to mean something.
_COST = {Scheme.INPROC: 0, Scheme.UNIX: 1, Scheme.TCP: 2}


@dataclass(frozen=True, slots=True)
class Address:
    """One place a peer might answer. `scheme:value`, e.g. `unix:/run/dude/node.sock`."""

    scheme: Scheme
    value: str

    @property
    def sort_key(self) -> tuple[int, str]:
        """Dial preference: cheapest carrier first, then by value for determinism.

        Explicit rather than `order=True` on the dataclass, for two reasons. Enum MEMBERS are not
        orderable, so derived ordering promised a sort it could not perform — and would have failed
        only at the moment a peer first advertised two carriers. And the derived order would have
        been by field order, i.e. alphabetical on the scheme name, which puts TCP ahead of a unix
        socket to the same peer. Stable but meaningless is not good enough."""
        return (_COST[self.scheme], self.value)

    def encode(self) -> bytes:
        return self.scheme.value + b":" + self.value.encode()

    @classmethod
    def parse(cls, raw: bytes) -> Self:
        """Parse a locator from the management store.

        Splits on the FIRST colon only: a TCP address contains one and a unix path may contain
        several, so anything else would mangle perfectly valid locators."""
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
    """Parse a peer's advertised addresses, DROPPING the ones we cannot dial.

    Silently skipping is right here and only here: a roster is shared by nodes with different
    transports compiled in, so "I cannot dial tcp" is a local capability fact, not a malformed
    record. Refusing the whole record would let one peer advertising an exotic carrier make itself
    unreachable to everyone — the failure would look like a roster problem rather than a build
    difference. Returns sorted, for a stable dial order."""
    out: list[Address] = []
    for raw in raws:
        try:
            out.append(Address.parse(raw))
        except AddressError:
            continue
    return tuple(sorted(out, key=lambda a: a.sort_key))


@dataclass(frozen=True, slots=True)
class Endpoint:
    """An address plus whatever options the manager wants that carrier to be given.

    WHY NOT CRAM IT ALL INTO THE URI [H]: a transport may need TLS material, a proxy, a mixnet
    profile, concurrency limits — things with structure. Encoding those as query parameters makes
    the address both a locator and a config file, and then every layer that merely wants to compare
    or sort addresses has to parse the whole thing.

    OPTIONS ARE OPAQUE ABOVE THE TRANSPORT, exactly as the envelope's `body` is opaque above the
    application. Only the implementation that dials this scheme interprets them; `Peer`, `Plan` and
    `Postman` pass them through without looking. That is what keeps carrier vocabulary out of
    everything else — an option nobody but the transport understands cannot leak upward.

    THE ADDRESS NAMES THE PATH; OPTIONS TUNE HOW IT IS USED. That division decides identity: a link
    is keyed on `(peer, address)`, so editing options keeps its measurements and its breaker state,
    which matters because resetting on any edit would reintroduce the silent un-breaking of a broken
    link that `Peer.reconfigure` exists to avoid. The corollary is a rule for whoever writes these:
    **if a setting changes where the bytes go, it belongs in the address, not the options.**"""

    address: Address
    options: Mapping[bytes, bytes] = field(default_factory=dict)

    def encode(self) -> bytes:
        """Canonical, so a manager's record is byte-identical across implementations."""
        return codec.encode([self.address.encode(), dict(sorted(self.options.items()))])

    @classmethod
    def parse(cls, raw: bytes) -> Endpoint:
        """Accepts a bare address too, so a roster written before options existed still reads.

        The one place liberality is right: it is not accepting a MALFORMED record, it is accepting a
        shorter well-defined one. LINKS.md's anti-rule forbids guessing at broken input, not
        supporting two explicit shapes."""
        try:
            decoded = codec.decode(raw)
        except codec.CodecError:
            # A bare `scheme:value` is not bencode at all, so the fallback has to sit HERE and not
            # after a successful decode — the first version of this method tested the decoded type
            # and never reached the branch, because decoding threw first.
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
    """Parse a peer's advertised endpoints, dropping any we cannot dial. See `parse_all`."""
    out: list[Endpoint] = []
    for raw in raws:
        try:
            out.append(Endpoint.parse(raw))
        except (AddressError, codec.CodecError):
            continue
    return tuple(sorted(out, key=lambda e: e.address.sort_key))
