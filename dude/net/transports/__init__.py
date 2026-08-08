# dude.net.transports — carriers. See SPEC.md (#transport-adds-no-trust).
#
# A package rather than a module, because a transport is the one thing here that genuinely
# multiplies: in-process, unix, tcp, and whatever a deployment adds. Each is small, each satisfies
# `link.Transport` and nothing more, and no other layer imports one directly — `Peer` receives a
# `dial` callable, so the choice of carrier reaches the system as a value rather than an import.
#
# THE CONTRACT IS DELIBERATELY TINY: move the bytes, or raise `LinkError`. No retries (a hidden
# retry is a transmission the link layer cannot count, which breaks Karn's rule and the retry budget
# at once), no timeouts, no state, no opinions about what it is carrying.
#
# SCHEME RESOLUTION LIVES HERE (#postman-owns-dialling), because this is the package that knows
# which carriers exist. `dial(endpoint, me)` is a CLOSED match over them — not a registry a
# deployment populates at startup. A build that links this package can dial every scheme it
# implements, the way `curl` resolves `https://` without being told which handler to use.

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
    """The SEND-side carrier for `endpoint`'s scheme, freshly constructed.

    Takes the whole `Endpoint` (so a carrier that needs its options gets them) and the
    caller's identity (so identity-bound carriers like InProc know who is dialling).
    Everything a dial-side carrier needs is in those two arguments — which is the reason
    this can be a closed match rather than something a caller injects.

    THE LISTEN SIDE IS NOT HERE, and cannot be. `TCPListener` needs a bind address, and an
    endpoint names where a PEER listens, which says nothing about where WE should. That is
    the one genuinely deployment-owned fact, so listeners are constructed by the deployment
    and handed to `Node.start`. Dial-side carriers are not: `TCPDialer()` takes no
    configuration at all, and `InProcDialer`'s is `me`.

    Raises `LinkError` for a scheme this build has no carrier for — the same failure a
    caller already handles from `send`."""
    match endpoint.address.scheme:
        case Scheme.INPROC:
            return InProcDialer(me=name_of(me.public))
        case Scheme.TCP:
            return TCPDialer()
        case _:
            raise LinkError(f"no carrier for scheme {endpoint.address.scheme.name}")
