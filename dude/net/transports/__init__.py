from __future__ import annotations

from ...core import crypto
from ..address import Endpoint, Scheme
from ..link import LinkError, Transport
from .inproc import InProcDialer, InProcListener, address_of, name_of
from .tcp import TCPDialer, TCPListener

__all__ = [
    "InProcDialer",
    "InProcListener",
    "TCPDialer",
    "TCPListener",
    "address_of",
    "dial",
    "name_of",
]


def dial(endpoint: Endpoint, me: crypto.Keypair) -> Transport:
    match endpoint.address.scheme:
        case Scheme.INPROC:
            return InProcDialer(me=name_of(me.public))
        case Scheme.TCP:
            return TCPDialer()
        case _:
            raise LinkError(f"no carrier for scheme {endpoint.address.scheme.name}")
