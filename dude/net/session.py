from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import NamedTuple

from ..core import crypto
from ..core.units import Millis
from .address import Address
from .envelope import Frame


class Session(ABC):
    identity: crypto.PublicKey | None
    address: Address
    last_activity: Millis
    on_close: Callable[[], None] | None

    def __init__(self, identity: crypto.PublicKey | None, address: Address) -> None:
        self.identity = identity
        self.address = address
        self.last_activity = 0
        self.on_close = None

    def bind(self, identity: crypto.PublicKey) -> None:
        """Rebinding to a DIFFERENT identity MUST raise: it is the only thing stopping one open
        pipe from impersonating several pubkeys."""
        if self.identity is not None:
            if self.identity != identity:
                raise SessionBindError(
                    f"session already bound to {self.identity.hex()[:8]}, "
                    f"refuses rebind to {identity.hex()[:8]}"
                )
            return
        self.identity = identity

    @abstractmethod
    def send(self, frame: Frame) -> None: ...

    @abstractmethod
    def close(self) -> None: ...


class SessionBindError(Exception): ...


class Inbound(NamedTuple):
    frame: Frame
    session: Session
    """Not Optional, by ruling. A sessionless carrier needs its own conversation, not a hole."""
