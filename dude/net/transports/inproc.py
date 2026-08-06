# dude.net.transports.inproc — a paired loopback with the same shape as TCP.
# See SPEC.md (#inproc-is-a-loopback, #partitions-are-test-only).
#
# What was here BEFORE the current split: a `Switchboard` object with shared inboxes and
# a partition table — a routing table that duplicated what Postman was supposed to do,
# plus test scaffolding smuggled into the transport. That defeated the point of InProc:
# **everything above the carrier gets exercised for real**. A routing table on top of
# the carrier meant Postman's own routing was untested.
#
# What's here NOW: TWO CONCRETE TYPES, mirroring the TCP shape:
#
#   InProcClient   send-only. Held by Postman via `attach_transport(Scheme.INPROC, ...)`.
#                  `send(address, frame)` looks the target up in the module-scope
#                  `_INBOXES` registry and appends to that listener's internal buffer.
#                  No state; construct one per Postman.
#   InProcListener receive-only. Registers itself in `_INBOXES` at construction under
#                  `name_of(identity)`; owns the internal buffer. Same `Listener`
#                  protocol as `TCPListener`: `start(inbox)` forwards to a queue in the
#                  simplest possible way (no threads needed -- appends happen on the
#                  send-side call), `stop()` unregisters, `drain()` returns buffered.
#
# Module-scope registry keyed by string name -- exactly the way TCP delegates to the
# kernel's socket table. Nothing between InProc instances but the module.
#
# NO PARTITION LOGIC (#partitions-are-test-only). Tests simulate a partition by removing
# the target from the sender's `postman.peers` via `Postman.remove_peer(pubkey)`;
# symmetric partition removes on both sides. That IS what a partition looks like to the
# protocol — the sender's routing table has no live path.

from __future__ import annotations

import queue
from collections import deque
from dataclasses import dataclass, field

from ...core import crypto
from ..address import Address, Scheme
from ..envelope import Frame
from ..link import LinkError, Listener, Transport

_INBOXES: dict[str, InProcListener] = {}
"""Module-scope registry of live `InProcListener` instances, keyed by the listener's
own name (from `name_of(identity)`). One entry per identity currently answering in
this process. Registration happens in `InProcListener.__post_init__`; deregistration
in `stop()`.

Module-scope deliberately: there is one Python process, one in-process address space.
Making it an object once created the illusion that multiple "networks" could coexist
and forced every construction path to plumb the object through — plumbing that ended
up nowhere near where the transport lived, defeating the point of #inproc-is-a-loopback.

`_reset_for_tests()` clears it — a test-hook, used only in test setup/teardown when
the registry might carry residual entries from a prior test."""


# --------------------------------------------------------------------------------------------- #
# Client -- outbound only, held by Postman                                                      #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class InProcClient(Transport):
    """InProc's send side. Stateless -- `send(address, frame)` looks the target
    `InProcListener` up in the module-scope `_INBOXES` registry and appends the frame
    to that listener's buffer directly. No thread, no socket, no delay.

    A `LinkError` from send means the target isn't registered (equivalent to
    connection-refused on TCP); Postman's link/breaker handles it the same way."""

    def send(self, address: Address, frame: Frame) -> None:
        if address.scheme is not Scheme.INPROC:
            raise LinkError(f"inproc cannot dial {address.scheme.value.decode()}")
        target = _INBOXES.get(address.value)
        if target is None:
            raise LinkError(f"no such in-process endpoint: {address.value}")
        target._deliver(frame)  # noqa: SLF001 -- same-module cooperative access


# --------------------------------------------------------------------------------------------- #
# Listener -- inbound only, held by Node                                                        #
# --------------------------------------------------------------------------------------------- #


@dataclass(slots=True)
class InProcListener(Listener):
    """InProc's receive side. Registers itself in `_INBOXES` under `name_of(identity)`
    at construction; other identities' `InProcClient.send()` finds us via that key.

    Two driver paths, one implementation:

      * PRODUCTION -- `start(inbox)` attaches a `SimpleQueue`; every subsequent
        `_deliver()` push flushes both the internal buffer AND the inbox.
      * TESTS -- `drain()` returns whatever's buffered internally right now,
        non-blocking, no thread.

    Unlike `TCPListener`, InProc has no background thread. Delivery happens on the
    SENDER's call to `InProcClient.send()`, in the sender's thread. `start(inbox)`
    exists to match the `Listener` protocol so `Node.start(*listeners)` treats every
    carrier uniformly; there's just no thread to spawn.

    Constructing two `InProcListener` instances with the same identity raises
    `LinkError` -- the registry rejects the collision, same as TCP would reject two
    servers binding the same port."""

    me: str
    _inbox_queue: queue.SimpleQueue[Frame] | None = field(init=False, default=None)
    _buffered: deque[Frame] = field(init=False, default_factory=deque)
    _stopped: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        if self.me in _INBOXES:
            raise LinkError(f"in-process name already registered: {self.me!r}")
        _INBOXES[self.me] = self

    def _deliver(self, frame: Frame) -> None:
        """Called by `InProcClient.send` when a peer sends TO us. Appends to the
        internal buffer AND (if `start()` has been called) forwards into the inbox
        queue. Same shape as `TCPListener._buffered + _inbox` -- but the "reader
        thread" is just the sender's call, since we're in-process."""
        if self._stopped:
            return  # stopped: silently drop, same as a closed TCP socket does
        self._buffered.append(frame)
        if self._inbox_queue is not None:
            self._inbox_queue.put(frame)
            self._buffered.clear()  # already forwarded; keep buffer empty

    def start(self, inbox: queue.SimpleQueue[Frame]) -> None:
        """Attach an inbox. Any frames already buffered flush into it immediately, and
        subsequent `_deliver` calls push straight through. Idempotent for the same
        inbox instance; a different one raises."""
        if self._inbox_queue is inbox:
            return
        if self._inbox_queue is not None:
            raise RuntimeError("InProcListener already started with a different inbox")
        self._inbox_queue = inbox
        for frame in self._buffered:
            inbox.put(frame)
        self._buffered.clear()

    def stop(self) -> None:
        """Unregister from `_INBOXES`, mark stopped. Idempotent. A closed listener that
        subsequently receives a send silently drops -- same as a stopped TCP listener
        would refuse the accept."""
        self._stopped = True
        self._inbox_queue = None
        _INBOXES.pop(self.me, None)

    def drain(self) -> tuple[Frame, ...]:
        """Non-blocking: return the internal buffer and clear it. Test-path driver
        (`start()` need not have been called). Same semantics as `TCPListener.drain()`."""
        out = tuple(self._buffered)
        self._buffered.clear()
        return out


# --------------------------------------------------------------------------------------------- #
# Helpers                                                                                       #
# --------------------------------------------------------------------------------------------- #


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
