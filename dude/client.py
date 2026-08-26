from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .core import codec, crypto
from .core.errors import DudeError
from .store import ops
from .store.management import MgmtReader


class ClientError(DudeError): ...


def name_bytes(name: str) -> bytes:
    """THE ONE PLACE a caller's string becomes the bytes a name token is derived from.

    NFC, because the same name typed on two platforms is not the same bytes otherwise: macOS hands
    you decomposed forms and Linux composed ones, so "café" would derive two different tokens,
    address two different rows, and read identically to every human who looked at either."""
    return unicodedata.normalize("NFC", name).encode("utf-8")


@dataclass(frozen=True, slots=True)
class Keys:
    """What one identity can read and write, unwrapped from the cluster's own management rows.

    Per store, because that is where the boundary is: a grant naming store 2 mints store 2's
    blinding secret and its epoch masters and nothing else, so an identity with no grant for a
    store cannot read it even holding its bytes. Cluster-wide keys would leave `stores` an access
    rule standing in for a key boundary -- the weaker of the two, and the one a stale replica or a
    misbehaving node ignores.

    A SNAPSHOT. Rotation mints a new epoch and a new wrap, so a `Keys` built before one does not
    know about it -- rebuild after a rotation rather than mutating this, which keeps "which keys do
    I hold" a question with one answer."""

    store_id: int
    blinding: crypto.Master
    masters: dict[int, crypto.Master]
    current: int

    """Holds MASTERS, not the keys derived from them. Derivation is one-way, so a keyring that
    kept only `EpochKeys` could read but could never mint another reader -- and minting is how a
    manager admits one, out of the wraps it holds itself."""

    @classmethod
    def unwrap(cls, mgmt: MgmtReader, me: crypto.Keypair, store_id: int = ops.STORE_DATA) -> Keys:
        blind = mgmt.blinding_wrap(store_id, me.public)
        if blind is None:
            raise ClientError(
                f"{me.public.hex()[:8]} holds no blinding secret for store {store_id}; "
                f"it was never minted a reader there"
            )
        masters: dict[int, crypto.Master] = {}
        for epoch, sealed in mgmt.wraps_for(store_id, me.public).items():
            try:
                masters[epoch] = crypto.Master(me.open_sealed_raw(sealed))
            except DudeError as e:
                # WHICH epoch, out of a keyring that may hold dozens.
                raise ClientError(f"wrap for epoch {epoch} would not open: {e}") from e
        return cls(
            store_id=store_id,
            blinding=crypto.Master(me.open_sealed_raw(blind)),
            masters=masters,
            current=mgmt.current_epoch(store_id),
        )

    @property
    def name_key(self) -> crypto.NameKey:
        return crypto.derive_name_key(self.blinding)

    def value_key(self, epoch: int) -> crypto.ValueKey:
        master = self.masters.get(epoch)
        if master is None:
            raise ClientError(
                f"no key for store {self.store_id} epoch {epoch}; minted before this grant"
            )
        return crypto.EpochKeys.derive(master).value_key

    def wraps_for(
        self, who: crypto.PublicKey
    ) -> tuple[dict[int, crypto.SealedBlob], crypto.SealedBlob]:
        """Everything a newcomer needs, sealed to it: EVERY epoch this holder can open, by default,
        so a reader minted after three rotations still reads what was written under the first.

        Only a holder can do this, and a manager is a holder precisely so it can -- it recovers any
        master by unsealing its own row, so an epoch minted without a manager in its wrap set can
        never be granted to anybody new."""
        return {e: who.seal(m) for e, m in self.masters.items()}, who.seal(self.blinding)


@dataclass(frozen=True, slots=True)
class Client:
    """Builds transactions and opens values. NO I/O: the same rules serve a node submission, a
    light-client read and whatever drives them next, and a second implementation of
    blinding-and-sealing is the shape this codebase keeps paying for.

    Returns `ops.Transaction` the way `MgmtWriter` does, so the caller signs and submits. A builder
    composing several of these into one dependent transaction sits on top of this, not inside it."""

    keys: Keys

    @property
    def store_id(self) -> int:
        """The store the keys are for. Not a separate setting: a client pointed at one store with
        another store's keys would blind and seal correctly and address nothing."""
        return self.keys.store_id

    def token(self, name: str) -> crypto.NameToken:
        return crypto.derive_name_token(self.keys.name_key, name_bytes(name))

    def _aad(self, token: crypto.NameToken, epoch: int) -> bytes:
        """Binds the ciphertext to its slot and its keyepoch, so one lifted into another name or
        another epoch fails to open even where the commitment layer would not have caught it."""
        return codec.encode([self.store_id, bytes(token), epoch])

    def seal(self, name: str, value: bytes) -> tuple[crypto.NameToken, bytes, int]:
        epoch = self.keys.current
        token = self.token(name)
        item = crypto.derive_item_key(self.keys.value_key(epoch), token)
        return token, bytes(crypto.AeadXcs1.seal(item, self._aad(token, epoch), value)), epoch

    def open(self, name: str, stored: bytes, epoch: int) -> bytes:
        """`epoch` comes from the row and sits under the SMT leaf, so a responder cannot name one
        of its own choosing without failing the proof."""
        token = self.token(name)
        item = crypto.derive_item_key(self.keys.value_key(epoch), token)
        return crypto.AeadXcs1.open(item, self._aad(token, epoch), crypto.AeadBlob(stored))

    def put(self, name: str, value: bytes) -> ops.Transaction:
        token, sealed, epoch = self.seal(name, value)
        return ops.writes(ops.Set(self.store_id, token, sealed, epoch))

    def delete(self, name: str) -> ops.Transaction:
        return ops.Transaction((ops.Step((), ops.Del(self.store_id, self.token(name))),))

    def cas(self, name: str, expect: bytes | None, value: bytes) -> ops.Transaction:
        """`expect` is the STORED bytes as read, not the plaintext. Sealing is randomised, so the
        same plaintext seals to different ciphertext every time and no guard can be computed from
        it -- compare-and-swap is against what the row actually holds."""
        token, sealed, epoch = self.seal(name, value)
        guard: ops.Predicate = (
            ops.Absent(self.store_id, token)
            if expect is None
            else ops.Holds(self.store_id, token, ops.value_digest(expect))
        )
        return ops.Transaction((ops.Step((guard,), ops.Set(self.store_id, token, sealed, epoch)),))


