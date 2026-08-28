
import time
from collections.abc import Callable

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import crypto
from ..net.postman import Postman
from ..net.transports.inproc import InProcListener, InProcNexus
from ..node import Node, ReplicaNode
from ..store import Store, ops
from ..session import Settled
from ..sync.lite_client import LightClient
from ..tunables import Tunables

T0 = 1_700_000_000_000

TUNABLES = Tunables(rtt_max=50, clock_skew=25, held_convergence_max=2)


class Cluster:

    def __init__(
        self,
        nodes: int = 3,
        mgmt: int = 1,
        ro: int = 0,
        rw: int = 0,
        tunables: Tunables | None = None,
    ):
        self.nexus: InProcNexus = {}
        self.tunables = tunables or TUNABLES
        self.anchor = crypto.Keypair.generate()

        node_keys = [crypto.Keypair.generate() for _ in range(nodes)]
        mgmt_keys = [crypto.Keypair.generate() for _ in range(mgmt)]
        ro_keys = [crypto.Keypair.generate() for _ in range(ro)]
        rw_keys = [crypto.Keypair.generate() for _ in range(rw)]

        self._genesis_bodies = self._genesis(node_keys, mgmt_keys, ro_keys, rw_keys)

        self.nodes: list[Node] = []
        for kp in node_keys:
            self._boot_node(kp)

        self.replicas: list[ReplicaNode] = []
        for kp in mgmt_keys:
            self.boot_replica(kp)

        self.ro_clients: list[LightClient] = []
        for kp in ro_keys:
            self._boot_light_client(kp, self.ro_clients)

        self.rw_clients: list[LightClient] = []
        for kp in rw_keys:
            self._boot_light_client(kp, self.rw_clients)

    # -- genesis ------------------------------------------------------------

    def _genesis(
        self,
        node_keys: list[crypto.Keypair],
        mgmt_keys: list[crypto.Keypair],
        ro_keys: list[crypto.Keypair],
        rw_keys: list[crypto.Keypair],
    ) -> tuple[ops.SignedTransaction, ...]:
        return compose_genesis(
            anchor=self.anchor,
            node_endpoints=[
                (kp.public, (InProcListener.endpoint_for(kp.public),))
                for kp in node_keys
            ],
            managers=mgmt_keys,
            ro_clients=ro_keys,
            rw_clients=rw_keys,
            ts=T0,
        )

    def provisioned(self) -> Store:
        s = Store()
        s.provision(self.anchor.public)
        bootstrap(s, self.anchor, self._genesis_bodies, bucket=self.tunables.bucket(T0))
        return s

    # -- adding participants ------------------------------------------------

    def _boot_node(self, kp: crypto.Keypair) -> Node:
        store = self.provisioned()
        node = Node(kp, store, self.tunables)
        node.add_listener(InProcListener(kp.public, self.nexus))
        node.start()
        self.nodes.append(node)
        return node

    def boot_replica(self, kp: crypto.Keypair) -> ReplicaNode:
        store = self.provisioned()
        rn = ReplicaNode(kp, store, self.tunables)
        rn.add_listener(InProcListener(kp.public, self.nexus))
        rn.start()
        self.replicas.append(rn)
        return rn

    def _boot_light_client(
        self, kp: crypto.Keypair, into: list[LightClient],
    ) -> LightClient:
        postman = Postman(kp, self.tunables)
        postman.add_listener(InProcListener(kp.public, self.nexus))
        lc = LightClient(me=kp, anchor=self.anchor.public, postman=postman)
        for node in self.nodes:
            lc.add_bootstrap_peer(
                node.me.public, (InProcListener.endpoint_for(node.me.public),),
            )
        lc.start()
        into.append(lc)
        return lc

    # -- waiting for convergence --------------------------------------------

    def _default_timeout(self, blocks: int = 10) -> float:
        floor = 3 * self.tunables.block_time / 1000
        return max(floor, blocks * self.tunables.block_time / 1000)

    def wait_head(
        self,
        target: int,
        timeout: float | None = None,
        nodes: list[Node | ReplicaNode] | None = None,
    ) -> None:
        check = nodes if nodes is not None else self.nodes
        current = min((n.store.head() for n in check), default=0)
        t = timeout if timeout is not None else self._default_timeout(target - current + 5)
        self.wait(lambda _: all(n.store.head() >= target for n in check), timeout=t)

    def wait_block(
        self,
        target: int,
        timeout: float | None = None,
        nodes: list[Node | ReplicaNode] | None = None,
    ) -> None:
        check = nodes if nodes is not None else self.nodes
        current = min(((n.store.head_block_num() or 0) for n in check), default=0)
        t = timeout if timeout is not None else self._default_timeout(target - current + 5)
        self.wait(
            lambda _: all((n.store.head_block_num() or 0) >= target for n in check),
            timeout=t,
        )

    def wait(self, predicate: Callable[["Cluster"], bool], timeout: float | None = None) -> None:
        t = timeout if timeout is not None else self._default_timeout()
        deadline = time.monotonic() + t
        while time.monotonic() < deadline:
            if predicate(self):
                return
            time.sleep(self.tunables.tick_interval / 1000)
        raise TimeoutError(f"predicate not satisfied within {t:.1f}s")

    def wait_settled(
        self, result: object, nodes: list[Node | ReplicaNode] | None = None,
    ) -> Settled:
        if not isinstance(result, Settled):
            raise AssertionError(f"expected Settled, got {result!r}")  # noqa: TRY004
        check = nodes if nodes is not None else self.nodes
        self.wait(lambda _: all(
            n.store.has_settled(result.op_hash) for n in check
        ))
        return result

    # -- teardown -----------------------------------------------------------

    def close(self) -> None:
        for lc in self.ro_clients + self.rw_clients:
            lc.stop()
        for rn in self.replicas:
            rn.stop()
        for node in self.nodes:
            node.stop()
