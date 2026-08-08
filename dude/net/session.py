# dude.net.session -- one open transport connection. See SPEC.md (#session-oriented-transport,
# and #session-first-reply, #session-bind-on-first-frame).
#
# The atomic unit is the connection, not the frame: a reply goes back the way the request came
# rather than being dialled to an advertised endpoint, which is the only path a client has (it is
# not in the roster and nothing can dial it).

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import NamedTuple

from ..core import crypto
from ..core.units import Millis
from .address import Address
from .envelope import Frame


class Session(ABC):
    """One open transport connection, bidirectional, identity-bound.

    A dial knows who it called and binds `identity` at construction; an accept learns it from
    the first inbound frame's `env.frm`, via `bind`.

    `on_close` fires when the connection dies. It MUST be idempotent: the transport's death
    path and `SessionLink`'s send-failure path both reach it, and they must converge."""

    identity: crypto.PublicKey | None
    address: Address
    """The peer's address through this session. NOT routing -- routing is by identity; carried
    so `Peer.sessions` ordering and diagnostics can name one session apart from another."""
    last_activity: Millis
    on_close: Callable[[], None] | None

    def __init__(self, identity: crypto.PublicKey | None, address: Address) -> None:
        self.identity = identity
        self.address = address
        self.last_activity = 0
        self.on_close = None

    def bind(self, identity: crypto.PublicKey) -> None:
        """Bind identity on the first inbound frame. Rebinding to a DIFFERENT identity raises:
        that is what stops one open pipe impersonating several pubkeys. Same identity is a
        no-op."""
        if self.identity is not None:
            if self.identity != identity:
                raise SessionBindError(
                    f"session already bound to {self.identity.hex()[:8]}, "
                    f"refuses rebind to {identity.hex()[:8]}"
                )
            return
        self.identity = identity

    @abstractmethod
    def send(self, frame: Frame) -> None:
        """Write `frame`. Raises `LinkError` on transport failure. Updates `last_activity` on
        success, so callers do not."""

    @abstractmethod
    def close(self) -> None:
        """Tear down the connection and fire `on_close`. Idempotent."""


class SessionBindError(Exception):
    """Two identities on one session. NOT a `DudeError`: this is our own contract check, not a
    class of wire error a peer can cause us to report."""


class Inbound(NamedTuple):
    """One inbound frame plus the session it arrived on.

    `session` is not Optional, by ruling: every supported transport produces sessions. A
    sessionless carrier would need its own conversation, not a hole here."""

    frame: Frame
    session: Session
