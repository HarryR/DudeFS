# dude.net.transports.inproc — a carrier with no I/O at all. See SPEC.md (#transport-adds-no-trust).
#
# Delivery by direct call into a shared switchboard. It exists so a whole cluster runs in one
# process with no sockets, no ports and no sleeping — which is what makes an end-to-end run a
# deterministic test rather than an integration environment.
#
# IT IS A REAL TRANSPORT, not a mock: it satisfies `link.Transport`, raises `LinkError` like any
# other carrier, and knows nothing about envelopes. Everything above it is exercised for real. The
# only thing it does not test is byte framing over a stream — the one concern the sealed frame
# already makes self-delimiting.
#
# DELIVERY IS QUEUED, NOT REENTRANT. `send` appends to the recipient's inbox and returns; it does
# not call into the recipient. A carrier that ran the peer's handler inline would let one node's
# send recurse into another's, making the call stack the real scheduler and hiding every ordering
# bug behind "it happened to work in one process".

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ...core import crypto
from ..address import Address, Scheme
from ..envelope import Frame
from ..link import LinkError, Transport


@dataclass(slots=True)
class Switchboard:
    """Where in-process nodes find each other. One per simulated network."""

    inboxes: dict[str, deque[Frame]] = field(default_factory=dict)
    partitioned: set[tuple[str, str]] = field(default_factory=set)
    """Directed cuts, `(from, to)`. A PARTITION IS A VALUE — no firewall, no container, no waiting.
    Directed rather than symmetric because a one-way cut is a real failure and the more revealing
    one: it produces a peer that hears everything and is never heard."""

    def bind(self, name: str) -> None:
        self.inboxes.setdefault(name, deque())

    def cut(self, frm: str, to: str) -> None:
        self.partitioned.add((frm, to))

    def heal(self, frm: str, to: str) -> None:
        self.partitioned.discard((frm, to))

    def deliver(self, frm: str, to: str, frame: Frame) -> None:
        if (frm, to) in self.partitioned:
            raise LinkError(f"partitioned: {frm} -> {to}")
        inbox = self.inboxes.get(to)
        if inbox is None:
            raise LinkError(f"no such endpoint: {to}")
        inbox.append(frame)

    def drain(self, name: str) -> tuple[Frame, ...]:
        """Everything waiting for `name`, removed. The caller feeds these to its postman, so a test
        drives delivery explicitly instead of it happening as a side effect of sending."""
        inbox = self.inboxes.get(name)
        if inbox is None:
            return ()
        out = tuple(inbox)
        inbox.clear()
        return out

    def pending(self) -> int:
        return sum(len(q) for q in self.inboxes.values())


@dataclass(slots=True)
class InProc(Transport):
    """One node's view of the switchboard: it knows who it is, so the cut can be directed."""

    me: str
    board: Switchboard

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.INPROC:
            raise LinkError(f"inproc cannot dial {address.scheme.value.decode()}")
        self.board.deliver(self.me, address.value, frame)


def name_of(identity: crypto.PublicKey) -> str:
    """A stable in-process address for an identity. Short prefix, because these end up in test
    output and a full key is unreadable there."""
    return identity.hex()[:12]


def address_of(identity: crypto.PublicKey) -> Address:
    return Address(Scheme.INPROC, name_of(identity))
