# dude.net.transports — carriers. See ../../../LINKS.md, ../../../TRANSPORT.md.
#
# A package rather than a module, because a transport is the one thing here that genuinely
# multiplies: in-process, unix, tcp, and whatever a deployment adds. Each is small, each satisfies
# `link.Transport` and nothing more, and no other layer imports one directly — `Peer` receives a
# `dial` callable, so the choice of carrier reaches the system as a value rather than an import.
#
# THE CONTRACT IS DELIBERATELY TINY: move the bytes, or raise `LinkError`. No retries (a hidden
# retry is a transmission the link layer cannot count, which breaks Karn's rule and the retry budget
# at once), no timeouts, no state, no opinions about what it is carrying.

from .inproc import InProc, Switchboard, address_of, name_of

__all__ = ["InProc", "Switchboard", "address_of", "name_of"]
