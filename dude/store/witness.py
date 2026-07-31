# dude.store.witness — what this node has HEARD, and what it has PROVED. See #cross-attestation.
#
# NODE-LOCAL, NOT LOG STATE, which is why it is a lens over the store rather than part of it. An
# accusation is not consensus: it is a pair of signatures that speaks for itself wherever it is
# carried, so it is never settled, never ratified, and never agreed. The log does not read any of it
# — nothing in `Store` calls into here — and that one-way dependency is what makes this a separate
# object rather than another section of a large one.
#
# IT OWNS ITS OWN TABLES, for the same reason. A node that never gossips holds two empty tables it
# was given by a module it does not use; here they exist because the lens was constructed.
#
# The one thing it does reach back for is `adopt`: a peer's claim carries the quorum-signed floor it
# stands on, and taking the statement while ignoring the floor it proves would be half an act.

from __future__ import annotations

import sqlite3

from ..core import crypto
from . import attest
from .store import Store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sighting (peer BLOB PRIMARY KEY, att BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS conviction (
    peer    BLOB PRIMARY KEY,
    fault   INTEGER NOT NULL,
    earlier BLOB NOT NULL,
    later   BLOB NOT NULL
);
"""


class Witness:
    """Peers' statements about themselves, and the convictions they complete.

    Constructed per use, like `Management` — it holds no state of its own beyond the connection it
    was handed, so a fresh one sees exactly what the last one wrote."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.db: sqlite3.Connection = store.db
        self.db.executescript(_SCHEMA)

    def heard(self, signed: attest.SignedAttestation) -> attest.Evidence | None:
        """Take a peer's statement. Returns the conviction it completes, if it completes one.

        THE RETENTION RULE, and the trap it avoids: the obvious "latest wins by seq" is WRONG,
        because a regression arrives with the highest counter and would therefore overwrite the
        very statement that proves it. So the contradiction is tested first and both halves are
        kept forever when it convicts.

        Unsigned bytes are dropped rather than stored: anyone can write an incriminating claim,
        and only the key can make it evidence."""
        if not signed.verify():
            return None
        held = self.sighting(signed.by)
        if held is not None:
            found = attest.contradiction(held, signed)
            if found is not None:
                self.db.execute(
                    "INSERT OR IGNORE INTO conviction (peer, fault, earlier, later)"
                    " VALUES (?,?,?,?)",
                    (
                        found.culprit,
                        found.fault.value,
                        found.earlier.encode(),
                        found.later.encode(),
                    ),
                )
                return found
            if signed.claim.seq <= held.claim.seq:
                return None  # stale relay; we already hold this or better
        self.db.execute(
            "INSERT OR REPLACE INTO sighting (peer, att) VALUES (?,?)",
            (signed.by, signed.encode()),
        )
        return None

    def judge(self, claimed: attest.Evidence) -> attest.Evidence | None:
        """Take evidence someone else assembled, and RECOMPUTE the verdict rather than believe it.

        The same principle as ratifying a collection: a relay's word is worth nothing and its
        signatures are worth everything. Recomputing costs two signature checks and means a peer
        cannot get an honest node shunned by asserting a fault that is not there."""
        found = attest.contradiction(claimed.earlier, claimed.later)
        if found is None:
            return None
        self.db.execute(
            "INSERT OR IGNORE INTO conviction (peer, fault, earlier, later) VALUES (?,?,?,?)",
            (found.culprit, found.fault.value, found.earlier.encode(), found.later.encode()),
        )
        return found

    def sighting(self, peer: crypto.PublicKey) -> attest.SignedAttestation | None:
        row = self.db.execute("SELECT att FROM sighting WHERE peer=?", (peer,)).fetchone()
        return attest.SignedAttestation.decode(row[0]) if row else None

    def sightings(self) -> tuple[attest.SignedAttestation, ...]:
        """Sorted by peer — never rowid order, which is a portability rule, not a style one."""
        return tuple(
            attest.SignedAttestation.decode(r[0])
            for r in self.db.execute("SELECT att FROM sighting ORDER BY peer")
        )

    def convictions(self) -> dict[crypto.PublicKey, attest.Evidence]:
        """Proven self-contradictions, kept forever. The evidence a manager acts on, and meanwhile
        the shun list — which is a local READ policy and changes no roster and no quorum."""
        out: dict[crypto.PublicKey, attest.Evidence] = {}
        for peer, fault, earlier, later in self.db.execute(
            "SELECT peer, fault, earlier, later FROM conviction ORDER BY peer"
        ):
            out[crypto.PublicKey(peer)] = attest.Evidence(
                attest.Fault(fault),
                attest.SignedAttestation.decode(earlier),
                attest.SignedAttestation.decode(later),
            )
        return out
