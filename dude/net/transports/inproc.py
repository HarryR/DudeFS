# dude.net.transports.inproc — a paired loopback with the same shape as TCP/UNIX.
# See SPEC.md (#inproc-is-a-loopback, #partitions-are-test-only).
#
# What was here BEFORE: a `Switchboard` object with shared inboxes and a partition table —
# a routing table that duplicated what Postman was supposed to do, plus test scaffolding
# smuggled into the transport. That defeated the point of InProc: **everything above the
# carrier gets exercised for real**. A routing table on top of the carrier meant Postman's
# own routing was untested.
#
# What's here NOW: a module-scope registry keyed by string name. An `InProc` transport is
# constructed for its own identity, registers itself in the module dict, and is
# unregistered on `close()`. Sending looks the target up in the module dict — exactly the
# way TCP delegates to the kernel's socket table. Nothing between InProc instances but the
# module.
#
# NO PARTITION LOGIC (#partitions-are-test-only). Tests that want to simulate a partition
# remove the target from the sender's `postman.peers` via `Postman.remove_peer(pubkey)`;
# symmetric partition removes on both sides. That IS what a partition looks like to the
# protocol — the sender's routing table has no live path.

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ...core import crypto
from ..address import Address, Scheme
from ..envelope import Frame
from ..link import LinkError, Transport

_INBOXES: dict[str, InProc] = {}
"""Module-scope registry of live `InProc` transports, keyed by the transport's own name.
One entry per identity currently running in this process. Registration happens in
`InProc.__post_init__`; deregistration in `close()`.

This is deliberately module-scope rather than an object passed around. There is one
Python process; there is one in-process address space. Making it an object created
the illusion that multiple "networks" could coexist and forced every construction path
to plumb the object through — plumbing that ended up nowhere near where the transport
lived, defeating the point of #inproc-is-a-loopback.

`_reset_for_tests()` clears it — a test-hook, used only in test setup/teardown."""


@dataclass(slots=True)
class InProc(Transport):
    """One identity's presence in the in-process transport space.

    Same shape as any other `Transport`:
      * `send(address, frame)` — bytes to a peer; raises `LinkError` if the peer is not
        currently registered (mirrors "connection refused" on TCP).
      * `receive()` — drain the frames addressed to us since the last call.

    `me` is the transport's own name (from `name_of(pubkey)`), which is what other InProc
    instances address when sending to us. Constructing two InProcs with the same name
    raises `LinkError` — the module registry rejects the collision, same as TCP would
    reject two servers binding the same port."""

    me: str
    _inbox: deque[Frame] = field(default_factory=deque)

    def __post_init__(self) -> None:
        if self.me in _INBOXES:
            raise LinkError(f"in-process name already registered: {self.me!r}")
        _INBOXES[self.me] = self

    def close(self) -> None:
        """Unregister. Idempotent — a caller that closes twice does not fail.

        A closed InProc that receives a send later raises `LinkError` on the sender's
        side (target not in registry). This models a peer that has stopped listening."""
        _INBOXES.pop(self.me, None)

    def send(self, address: Address, frame: Frame) -> None:
        """Deliver `frame` to whoever holds `address.value` in the module registry.
        Raises `LinkError` if nobody is registered under that name (the equivalent of
        connection refused on a real carrier)."""
        if address.scheme is not Scheme.INPROC:
            raise LinkError(f"inproc cannot dial {address.scheme.value.decode()}")
        target = _INBOXES.get(address.value)
        if target is None:
            raise LinkError(f"no such in-process endpoint: {address.value}")
        target._inbox.append(frame)  # noqa: SLF001 -- same-module private-field access

    def receive(self) -> tuple[Frame, ...]:
        """Drain everything waiting for us since the last call, in arrival order.
        Postman polls this once per tick to pull inbound frames into the mailbox layer."""
        out = tuple(self._inbox)
        self._inbox.clear()
        return out


def _reset_for_tests() -> None:
    """Clear the module registry. Test-only hook; production has no reason to call it.

    Named with a leading underscore and the `_for_tests` suffix so a production caller
    that reaches for this raises the reviewer's eyebrow immediately."""
    _INBOXES.clear()


def name_of(identity: crypto.PublicKey) -> str:
    """A stable in-process address for an identity. Short prefix, because these end up in
    test output and a full key is unreadable there."""
    return identity.hex()[:12]


def address_of(identity: crypto.PublicKey) -> Address:
    return Address(Scheme.INPROC, name_of(identity))
