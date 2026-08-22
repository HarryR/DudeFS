from __future__ import annotations

from dataclasses import dataclass

from ..consensus.settle_round import Anchors, SettledBlock, _settle_payload
from ..core import codec, crypto
from .errors import StoreError
from .management import Authorization, Cert, Role


class CheckpointError(StoreError): ...


_CHECKPOINT_DOMAIN = b"dude.checkpoint:"


@dataclass(frozen=True, slots=True)
class CheckpointMeta:
    settled_block_bytes: bytes
    anchor: crypto.PublicKey
    compactor: crypto.PublicKey
    grant_cert: Cert
    sig: crypto.Signature

    @classmethod
    def create(
        cls,
        settled_block_bytes: bytes,
        anchor: crypto.PublicKey,
        compactor: crypto.Keypair,
        grant_cert: Cert,
    ) -> CheckpointMeta:
        payload = _checkpoint_payload(settled_block_bytes, anchor)
        return cls(
            settled_block_bytes=settled_block_bytes,
            anchor=anchor,
            compactor=compactor.public,
            grant_cert=grant_cert,
            sig=compactor.sign(payload),
        )

    def settled_block(self) -> SettledBlock:
        return SettledBlock.decode(self.settled_block_bytes)

    @property
    def anchors(self) -> Anchors:
        return self.settled_block().anchors

    @property
    def state_root(self) -> crypto.Digest:
        return self.anchors.state_root

    @property
    def block_hash(self) -> crypto.Digest:
        return self.settled_block().block_hash

    def verify_compactor(self, known_anchor: crypto.PublicKey) -> str | None:
        if self.anchor != known_anchor:
            return "checkpoint anchor does not match known anchor"
        gc = self.grant_cert
        if gc.signer != known_anchor:
            return "compactor grant not signed by anchor"
        if gc.purpose != Role.COMPACTOR.value:
            return f"grant purpose is {gc.purpose!r}, not COMPACTOR"
        if gc.subject != bytes(self.compactor) or not gc.verify():
            return "compactor grant invalid"
        payload = _checkpoint_payload(self.settled_block_bytes, self.anchor)
        if not self.compactor.verify(payload, self.sig):
            return "compactor signature invalid"
        return None

    def verify_quorum(
        self, roster: tuple[crypto.PublicKey, ...],
    ) -> str | None:
        sb = self.settled_block()
        payload = _settle_payload(sb.block.slice_hash, sb.anchors)
        auth = Authorization(sb.multisig, payload, roster, self.anchor)
        if not auth.verify():
            return "quorum multisig on pivot block does not verify"
        return None

    def encode(self) -> bytes:
        return codec.encode([
            self.settled_block_bytes,
            self.anchor,
            self.compactor,
            self.grant_cert.encode(),
            self.sig,
        ])

    @classmethod
    def decode(cls, raw: bytes) -> CheckpointMeta:
        try:
            p = codec.as_seq(codec.decode(raw), 5)
            return cls(
                settled_block_bytes=codec.as_bytes(p[0]),
                anchor=crypto.PublicKey(codec.as_bytes(p[1])),
                compactor=crypto.PublicKey(codec.as_bytes(p[2])),
                grant_cert=Cert.decode(codec.as_bytes(p[3])),
                sig=crypto.Signature(codec.as_bytes(p[4])),
            )
        except StoreError as e:
            raise CheckpointError(f"malformed CheckpointMeta: {e}") from e


def _checkpoint_payload(settled_block_bytes: bytes, anchor: crypto.PublicKey) -> bytes:
    return _CHECKPOINT_DOMAIN + codec.encode([settled_block_bytes, anchor])
