# Shared builders for the L4 tests (transport + sim): honest LocalNode clusters
# whose clocks read an injected `now`, plus config/op sugar.

from __future__ import annotations

from collections.abc import Callable

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import node as N
from dudefs.acceptor import Acceptor
from dudefs.quorum import QuorumConfig
from dudefs.store import ChainStore
from tests._builders import World


def make_cluster(
    n: int, clock: Callable[[], int], delta: int = 10_000
) -> tuple[list[N.LocalNode], list[bytes]]:
    """n honest LocalNodes (config epoch 0) sharing one injected clock."""
    nodes = []
    for i in range(n):
        sk = bytes([200 + i] * 32)
        pub = C.SIGNER.public(sk)
        acc = Acceptor(sk, pub, ChainStore(), config_epoch=0, delta_ms=delta)
        nodes.append(N.LocalNode(acc, clock))
    return nodes, [nd.acc.pub for nd in nodes]


def cfg_for(roster: list[bytes], client_pub: bytes, **kw) -> QuorumConfig:
    return QuorumConfig(roster=roster, epoch=0, client_fp=A.fingerprint(client_pub), **kw)


def creation_op(w: World, ci: int, val: bytes) -> A.Op:
    """A creation CAS on key `k` (absent -> val) authored by client `ci`."""
    return w.cas(
        ci, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", val]]
    )
