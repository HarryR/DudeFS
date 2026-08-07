# dude.net.session -- Session, the first-class object representing one open transport connection.
#
# WHY THIS TYPE EXISTS. Before: transports (`TCPListener`, `InProcListener`) pushed bare `Frame`s
# into an inbox. The receive side had no way to reply on the same connection; every reply had to
# be dialed back to the requester's advertised endpoint via `Postman.peers`. That worked for nodes
# (which are dialable roster members) and broke for clients (which are not). It also foreclosed
# the natural multi-homing win of "peer B is currently connected to us, prefer that over dialing
# back".
#
# THE ATOMIC UNIT is one open connection. A dial produces a `Session`; an accept produces a
# `Session`. Both are bidirectional -- `send()` writes, and inbound frames the transport reads on
# that connection get pushed into the inbox tagged with their `Session`. Identity is bound at
# construction (dial-time, when we know who we're calling) or via `bind()` on the first inbound
# frame's `env.frm` (accept-time, when we learn who the caller is). Subsequent inbound frames on
# the same session that carry a different `env.frm` are a contract violation and close the session.
#
# NOT A HANDLE, AN OBJECT. Nothing above the transport layer needs to know about sockets, fds,
# selector keys, or whatever the transport uses internally. Callers hold a `Session` and call its
# methods. The transport owns whatever bookkeeping the underlying carrier requires.
#
# SESSION IS MANDATORY. Every transport this codebase supports produces sessions -- there is no
# `Session | None` seam. A hypothetical sessionless carrier (mixnet-style overlay, XMPP-message)
# would need its own architectural conversation, not a quiet Optional here.

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

    Two paths produce a Session, both yield the same interface:
      * `Dialer.dial(address, identity) -> Session` -- we initiate; `identity` is bound at
        construction (we know who we called).
      * `Listener` accept-loop -- something dialed us; `identity` starts as `None` and is set
        by `bind(env.frm)` on the first inbound frame (call site is `Postman.deliver`).

    LIFETIME: from creation (dial or accept) to `close()`. The transport that owns the Session
    reads inbound bytes and pushes each complete frame into the caller's inbox as an
    `Inbound(frame, session)`. The Session's own `send(frame)` writes outbound on the same
    connection.

    IDENTITY CONTRACT: `bind()` sets identity exactly once. A frame arriving on this session
    whose `env.frm` differs from `identity` (after binding) is a contract violation -- the
    session is closed and the frame refused. This is what stops a misbehaving connection from
    impersonating multiple pubkeys through one open pipe.

    `on_close` HOOK: transport calls this when the underlying connection dies (peer close, OS
    reset, whatever). Set by `Postman.register_session` to the SessionLink's `_close()`, which
    unregisters the link from the peer. Idempotent -- extra calls are no-ops -- because
    SessionLink's own send-failure path also calls `close()`, and both paths must converge."""

    identity: crypto.PublicKey | None
    address: Address
    """The peer's address as seen through this session (accepted-from for inbound,
    dialed-to for outbound). Not used for routing (routing is by identity) -- carried so
    `Peer.sessions` sorting and diagnostics can name the session distinctly."""
    last_activity: Millis
    on_close: Callable[[], None] | None

    def __init__(self, identity: crypto.PublicKey | None, address: Address) -> None:
        self.identity = identity
        self.address = address
        self.last_activity = 0
        self.on_close = None

    def bind(self, identity: crypto.PublicKey) -> None:
        """Bind identity on first inbound frame. Second call with a DIFFERENT identity is a
        contract violation; second call with the SAME identity is idempotent (no-op)."""
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
        """Write `frame` on this connection. Raises `LinkError` on transport failure. The
        Session updates `last_activity` on success; callers don't need to."""

    @abstractmethod
    def close(self) -> None:
        """Tear down the underlying connection AND fire `on_close` if set. Idempotent -- extra
        calls are no-ops."""


class SessionBindError(Exception):
    """Two identities on one session. The transport closes the connection and drops the frame;
    NOT a DudeError because this is an OUR-side contract check, not a wire error class."""


class Inbound(NamedTuple):
    """One inbound frame plus the session it arrived on. Every listener pushes this shape into
    the caller's inbox -- the `Frame` gets dispatched normally, and `Session` is what
    `Postman.deliver` uses to bind identity on first sight and to reach for a return path
    later.

    Non-Optional `session` by ruling: every supported transport produces sessions. A future
    sessionless carrier needs its own conversation, not a hole here."""

    frame: Frame
    session: Session
