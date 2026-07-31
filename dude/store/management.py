# dude.store.management — the management store, as an API. See SPEC.md (#management-is-cleartext).
#
# Two halves, and the split is the whole point:
#
#   READS   derive from the store by replay. No secrets, no I/O, no network.
#   WRITES  RETURN AN UNSIGNED `Transaction`. They never apply anything, and never sign.
#
# Because a write returns an unsigned transaction rather than performing anything, several compose
# with `+` into ONE atomic unit — which is how #roster-change-is-atomic's "one transaction, not a
# sequence" gets
# enforced by the shape of the API instead of by remembering. A caller composes the mutations from
# several helpers with `+`, signs the union ONCE, and applies that — so a partial removal
# (a node out of the roster but still holding a live master) is not a state the API can reach.
#
# and it satisfies #one-write-vocabulary: there is no compound `remove_node` OPERATION, only a
# helper emitting `set` and `del`. Nothing here is a new opcode.
#
# KEYS ARE CLEARTEXT PATHS, not derived tokens. #management-is-cleartext makes control operations
# readable to
# nodes — they must be, since a node needs the node set and the ACL to function — and it must
# ENUMERATE node records, which opaque fixed-width digests cannot support. So the management
# store is a plain prefixed keyspace and `Store.prefix` is how it is read.

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from .. import quorum
from ..core import codec, crypto
from ..core.errors import DudeError
from . import ops
from .layer import Index, Reader

# A transport locator, opaque here on purpose: the management store records WHERE a node can be
# reached as a string, and `dude.net` owns what the string means. Keeping the parse out of the store
# is what stops carrier vocabulary leaking into the log (#transport-adds-no-trust — transport adds
# no trust).
type Address = bytes


class ManagementError(DudeError):
    """A management record that is absent, malformed, or contradicts itself."""


class Role(Enum):
    """Who someone is. Coarse, per #coarse-acl — the grant is by store or by operation kind, never
    by path prefix, because a node must check it without reading a key
    (#management-is-cleartext)."""

    MANAGER = b"manager"
    NODE = b"node"
    CLIENT = b"client"
    COMPACTOR = b"compactor"


type Domain = bytes
"""A failure-domain label, e.g. `b"provider:hetzner"`, `b"country:de"`, `b"asn:24940"`.

**OPAQUE.** Nothing in this package parses one — the prefix convention is for humans, and the code
only
ever COUNTS. That is what lets a deployment add axes (`rack:`, `psu:`, `cable:`) later without a
schema
change or a version bump."""


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """A node's membership record. Its PRESENCE is membership (#presence-is-membership);
    deletion is removal."""

    identity: crypto.PublicKey
    addresses: tuple[Address, ...]
    domains: frozenset[Domain] = frozenset()
    """Which failure domains this node shares with others. Rack-aware placement, generalised:
    when one
    rack burns, you do not want the replacement in the rack beside it."""


@dataclass(frozen=True, slots=True)
class Grant:
    """What an identity may write. `stores` is the set of store ids; `kinds` the operation kinds
    (the compactor's grant is a KIND, not a store — there is no compaction store, #coarse-acl)."""

    identity: crypto.PublicKey
    role: Role
    stores: frozenset[int]
    kinds: frozenset[int]


# --------------------------------------------------------------------------- #
# Key layout. One prefix per record type, so each is a range scan.             #
# --------------------------------------------------------------------------- #

P_NODE = b"node/"  # + identity          -> [addr, ...]
P_GRANT = b"grant/"  # + identity        -> [role, [store...], [kind...]]
P_POP = b"pop/"  # + identity            -> possession proof, from issuance (#possession-proof)
P_WRAP = b"wrap/"  # + epoch + identity  -> sealed master (#wrapped-masters)
P_ROSTER = b"roster"  # one key      -> [serial, [member, ...]] (#bootstrap-anchor step 7)


def _wrap_key(epoch: int, who: crypto.PublicKey) -> bytes:
    # epoch is fixed-width big-endian so the keyspace sorts by epoch, making "every wrap for epoch
    # N" a prefix scan rather than a filter.
    return P_WRAP + epoch.to_bytes(8, "big") + who


class Management:
    """The management store, read and written through one place.

    Self-contained by design: a caller that holds this needs no other knowledge of how membership,
    authorisation or key distribution are encoded."""

    def __init__(self, store: Reader, store_id: int = ops.STORE_MANAGEMENT):
        self.store = store
        self.store_id = store_id

    # -- reads ---------------------------------------------------------------- #

    def nodes(self) -> dict[crypto.PublicKey, NodeRecord]:
        """Every node currently in the roster. A prefix scan (#presence-is-membership:
        presence is membership)."""
        out: dict[crypto.PublicKey, NodeRecord] = {}
        for name, _prov, value, _ep in self.store.prefix(self.store_id, P_NODE):
            who = crypto.PublicKey(name[len(P_NODE) :])
            rec = codec.decode(value)
            # A bare address list is the pre-domains shape. Accepted because it is a shorter
            # well-defined form, not a malformed one — the same latitude `Endpoint.parse` takes.
            if isinstance(rec, list | tuple) and rec and isinstance(rec[0], list | tuple):
                f = codec.as_seq(rec, 2)
                addrs = tuple(codec.as_bytes(a) for a in codec.as_seq(f[0]))
                doms = frozenset(codec.as_bytes(d) for d in codec.as_seq(f[1]))
            else:
                addrs = tuple(codec.as_bytes(a) for a in codec.as_seq(rec))
                doms = frozenset()
            out[who] = NodeRecord(who, addrs, doms)
        return out

    def node_set(self) -> tuple[crypto.PublicKey, ...]:
        """The roster as a sorted tuple — sorted because a signer bitmap indexes into it, and two
        implementations must agree on the order. Never rely on mapping iteration order for this:
        Go randomises it, so an unsorted roster would produce different bitmaps per language."""
        return tuple(sorted(self.nodes()))

    def addresses_of(self, who: crypto.PublicKey) -> tuple[Address, ...]:
        """Where `who` can be reached. A node may be multi-homed; `dude.net` chooses among them."""
        rec = self.nodes().get(who)
        return rec.addresses if rec else ()

    def roster_commitment(self) -> tuple[int, tuple[crypto.PublicKey, ...]] | None:
        """The manager's signed statement of WHO THE MEMBERS ARE, and which revision it is.

        STEP 7 OF THE CHAIN (#bootstrap-anchor). Enumerating `node/` rows tells a holder of state
        who the members are; it cannot tell a party HANDED some rows that it received all of
        them, and a subset is a smaller roster, which is a smaller quorum. One value the manager
        signed closes that: a subset of a list is not that list.

        THE SERIAL MAKES A STALE ROSTER DETECTABLE, by the argument the floor rests on: an adversary
        can withhold a newer commitment but cannot forge a higher serial without the manager's key,
        so believing the highest one you can verify is correct rather than credulous. Without it a
        genuine-but-superseded roster — members since removed, whose keys an adversary may still
        hold — verifies perfectly."""
        raw = self.store.get(self.store_id, P_ROSTER)
        if raw is None:
            return None
        f = codec.as_seq(codec.decode(raw[1]), 2)
        members = tuple(crypto.PublicKey(codec.as_bytes(m)) for m in codec.as_seq(f[1]))
        return codec.as_int(f[0]), members

    def set_roster(self, members: Iterable[crypto.PublicKey], serial: int) -> ops.Transaction:
        """Emit the commitment for a membership set. SORTED, because the value is compared byte for
        byte against an enumeration and two orderings of one set must not be two commitments."""
        record = codec.encode([serial, sorted(bytes(m) for m in members)])
        return ops.writes(ops.Set(self.store_id, P_ROSTER, record))

    def grant_of(self, who: crypto.PublicKey) -> Grant | None:
        raw = self.store.get(self.store_id, P_GRANT + who)
        if raw is None:
            return None
        f = codec.as_seq(codec.decode(raw[1]), 3)
        try:
            role = Role(codec.as_bytes(f[0]))
        except ValueError as e:
            raise ManagementError(f"unknown role for {who.hex()[:8]}") from e
        return Grant(
            who,
            role,
            frozenset(codec.as_int(x) for x in codec.as_seq(f[1])),
            frozenset(codec.as_int(x) for x in codec.as_seq(f[2])),
        )

    def may_write(self, reader: Reader, who: crypto.PublicKey, store_id: int) -> bool:
        """#coarse-acl's coarse check, and the ONLY authority question a node can answer blind: the
        store id is cleartext in every operation (#coarse-acl), so this needs no key and no path.

        Takes the `reader` per call so it satisfies `settle.Authoriser`: during evaluation that is
        the transaction's own layer, which is how a grant made by an earlier STEP is visible to a
        later step's check (authorise -> use -> revoke, in one atomic transaction)."""
        g = (
            Management(reader, self.store_id).grant_of(who)
            if reader is not self.store
            else self.grant_of(who)
        )
        if g is None:
            return False
        return g.role is Role.MANAGER or store_id in g.stores

    def may_send(self, who: crypto.PublicKey, kind: int) -> bool:
        """Whether `who` may author an operation of this kind — the grant that has no store, e.g. a
        compaction (#coarse-acl)."""
        g = self.grant_of(who)
        if g is None:
            return False
        return g.role is Role.MANAGER or kind in g.kinds

    def possession_proof(self, who: crypto.PublicKey) -> crypto.Signature | None:
        raw = self.store.get(self.store_id, P_POP + who)
        return crypto.Signature(raw[1]) if raw else None

    def wrapped_master(self, epoch: int, who: crypto.PublicKey) -> crypto.SealedBlob | None:
        """`who`'s sealed copy of the epoch master (#wrapped-masters). Opening it is the
        holder's business;
        this layer never sees a secret."""
        raw = self.store.get(self.store_id, _wrap_key(epoch, who))
        return crypto.SealedBlob(raw[1]) if raw else None

    # -- writes: emit mutations, apply nothing -------------------------------- #

    def add_node(
        self,
        who: crypto.PublicKey,
        addresses: tuple[Address, ...],
        domains: frozenset[Domain] = frozenset(),
        rule: quorum.Rule = quorum.DEFAULT,
    ) -> ops.Transaction:
        """Admit a node, REFUSING a roster that would violate the failure-domain bound.

        NOTE THE GROWTH CONSTRAINT, found by implementing this. The bound TIGHTENS as `n`
        falls, so a
        roster that is sound at its target size may be unreachable one node at a time:
        3-3-3-2 across
        four providers is fine at n=11, but at n=4 the bound is 1 and the third node of the first
        provider is refused. A target roster must therefore be reached by a BATCHED roster change,
        not by repeated `add_node` -- which is the same reason growth goes through `change_roster`
        rather than repeated promotion.

        Checked here rather than left to an operator, because the failure mode is silent: a
        roster can
        look diverse — eleven countries — while three of them are one billing account. And note that
        ADDING a node can REDUCE effective tolerance, since `f` falls out of `n`."""
        after = dict(self.nodes())
        after[who] = NodeRecord(who, addresses, domains)
        bad = _violations(after, rule)
        if bad:
            raise ManagementError(
                "failure-domain bound exceeded: "
                + ", ".join(f"{d.decode(errors='replace')}={c}" for d, c in sorted(bad.items()))
                + f" > {rule.max_domain(len(after))} allowed at n={len(after)}"
            )
        return ops.writes(
            ops.Set(
                self.store_id,
                P_NODE + who,
                codec.encode([list(addresses), sorted(domains)]),
            )
        )

    def domain_groups(self) -> dict[Domain, frozenset[crypto.PublicKey]]:
        """Which nodes share each label. A pure fold over the roster."""
        groups: dict[Domain, set[crypto.PublicKey]] = {}
        for rec in self.nodes().values():
            for d in rec.domains:
                groups.setdefault(d, set()).add(rec.identity)
        return {d: frozenset(m) for d, m in groups.items()}

    def check_domains(self, rule: quorum.Rule = quorum.DEFAULT) -> dict[Domain, int]:
        """Domains over the bound, empty if the roster is sound. Callable by anyone, any time."""
        return _violations(self.nodes(), rule)

    def remove_node(self, who: crypto.PublicKey) -> ops.Transaction:
        """Removal ALONE. Forward secrecy needs the rotation that follows, and
        #roster-change-is-atomic says the
        two belong in one transaction — compose this with `distribute`, do not call it alone."""
        return ops.writes(ops.Del(self.store_id, P_NODE + who))

    def authorise(
        self,
        who: crypto.PublicKey,
        role: Role,
        stores: frozenset[int] = frozenset(),
        kinds: frozenset[int] = frozenset(),
        pop: crypto.Signature | None = None,
    ) -> ops.Transaction:
        """Authorise an identity. `pop` is the subject's proof that it holds the secret half — the
        manager never certifies a key it did not see proven (#possession-proof), so this
        refuses without it
        rather than trusting the caller to have checked."""
        if pop is None or not who.verify_possession(pop):
            raise ManagementError(f"no valid possession proof for {who.hex()[:8]}")
        record = codec.encode([role.value, sorted(stores), sorted(kinds)])
        return ops.writes(
            ops.Set(self.store_id, P_GRANT + who, record),
            ops.Set(self.store_id, P_POP + who, pop),
        )

    def revoke(self, who: crypto.PublicKey) -> ops.Transaction:
        """Forward-only (#absence-is-revocation): operations this identity already authored
        stay valid, because
        validity is relative to the position at which they were authorised."""
        return ops.writes(
            ops.Del(self.store_id, P_GRANT + who),
            ops.Del(self.store_id, P_POP + who),
        )

    def distribute(
        self, epoch: int, wraps: dict[crypto.PublicKey, crypto.SealedBlob]
    ) -> ops.Transaction:
        """One wrapped master per authorised holder, for one keyepoch (#wrapped-masters).

        Atomicity is the point: every holder gains the secret together or none does, so no client is
        left holding data it cannot read. Sorted so two implementations emit identical mutations."""
        return ops.writes(
            *(ops.Set(self.store_id, _wrap_key(epoch, who), wraps[who]) for who in sorted(wraps))
        )

    # -- historical node sets ------------------------------------------------- #

    def node_set_at(self, _idx: Index) -> tuple[crypto.PublicKey, ...]:
        """NOT IMPLEMENTED, deliberately, and the reason is worth reading.

        #replay-does-not-readjudicate says an endorsement is valid for the node set in force
        *at its position*, which
        invites a historical query. But compaction may have collected the management operations that
        would answer it — a node added and later removed annihilates entirely (#accumulators) — so
        for old enough positions the answer is genuinely unrecoverable.

        That is not a gap, because nothing needs it: replay does not re-adjudicate
        (#replay-does-not-readjudicate), and a replayer's check is the accumulator against a quorum
        attestation (#collection-is-ratified). Historical
        node sets are needed only to verify an endorsement *while in use*, which is near-current.

        Left as an explicit refusal rather than absent, so a caller reaching for it discovers
        the reasoning instead of writing a version that is wrong past the compaction horizon."""
        raise ManagementError(
            "historical node sets are not reconstructible past compaction; verify against the "
            "attested accumulator instead (#collection-is-ratified)"
        )


def _violations(nodes: dict[crypto.PublicKey, NodeRecord], rule: quorum.Rule) -> dict[Domain, int]:
    """Labels held by more nodes than the rule allows. One invariant, no per-axis logic."""
    limit = rule.max_domain(len(nodes))
    if limit < 1:
        # A roster too small to tolerate ANY loss -- at n<=3 two-thirds gives max_domain 0. The
        # bound has nothing to say there: no placement makes a 1-node roster survivable, so
        # it would forbid the FIRST node and make bootstrap impossible. Found by implementing it.
        return {}
    counts: dict[Domain, int] = {}
    for rec in nodes.values():
        for d in rec.domains:
            counts[d] = counts.get(d, 0) + 1
    return {d: c for d, c in counts.items() if c > limit}
