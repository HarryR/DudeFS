from __future__ import annotations

from enum import Enum


class SyncRefusal(Enum):
    """ONE vocabulary for both sync paths. A node's block pull and a light client's read refused
    in two private enums that overlapped on `INVALID` and `NOT_YET_SETTLED` and disagreed about
    everything else, so neither side could match a peer's refusal exhaustively and both ended up
    discarding the reason. Each side carries members it cannot itself produce; that is the price
    of one vocabulary, and an exhaustive match is what makes a new member impossible to ignore.

    Wire form is `.value`, so these strings are protocol. Renaming one is a wire break."""

    INVALID = "invalid"
    """Ordinal 0. A zero-valued field must never decode to a real reason."""

    NOT_YET_SETTLED = "not-yet-settled"

    UNKNOWN = "unknown"

    NO_STATE = "no-state"

    UNKNOWN_STORE = "unknown-store"

    MALFORMED_QUERY = "malformed-query"

    FORK_DETECTED = "fork-detected"

    INTERNAL = "internal"

    UNAUTHORISED = "unauthorised"
    """The requester holds no standing for what they asked. Answered MALFORMED_QUERY before,
    which told an honest caller their request was malformed when it was their grant that was."""
