# dude.net — the wire. Three layers, kept apart (SPEC.md #transport-adds-no-trust).
#
#   inner     authenticated content, DISTRIBUTABLE  (dude.store.ops.SignedTransaction)
#   envelope  one hop, sender-authenticated, addressed, correlated, timestamped and GATED
#   sealing   transport confidentiality and nothing else
#
# Transports live below all three and add no trust whatsoever: a message is point-to-point even when
# the carrier is broadcast.

from .address import Address, AddressError, Scheme, parse_all
from .envelope import (
    MESSAGE_ID_SIZE,
    Envelope,
    EnvelopeError,
    Frame,
    MessageId,
    SignedEnvelope,
    Verb,
    new_message_id,
    request,
)
from .mailbox import Attempt, Expired, Expiry, Mailbox, Reply, Transmit
from .postman import Postman

__all__ = [
    "MESSAGE_ID_SIZE",
    "Address",
    "AddressError",
    "Attempt",
    "Envelope",
    "EnvelopeError",
    "Expired",
    "Expiry",
    "Frame",
    "Mailbox",
    "MessageId",
    "Postman",
    "Reply",
    "Scheme",
    "SignedEnvelope",
    "Transmit",
    "Verb",
    "new_message_id",
    "parse_all",
    "request",
]
