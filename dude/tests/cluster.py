import time
from abc import ABC, abstractmethod
from collections.abc import Callable

from ..consensus.bootstrap import bootstrap, compose_genesis
from ..core import crypto
from ..core.units import Millis
from ..net.address import Endpoint
from ..net.postman import OutputQueue, Postman
from ..net.transports.inproc import InProcNexus
from ..net.transports.tcp import TCPListener
from ..node import Node, ReplicaNode
from ..participant import Participant
from ..session import Settled
from ..store import Store, ops
from ..sync.lite_client import LightClient
from ..tunables import Tunables

T0 = Millis(1_700_000_000_000)

TUNABLES = Tunables(rtt_max=Millis(50), clock_skew=Millis(25), held_convergence_max=2)


class Fabric(ABC):
    @abstractmethod
    def endpoint_for(self, pub: crypto.PublicKey) -> Endpoint: ...

    @abstractmethod
    def attach(self, target: Participant | Postman) -> None: ...


class InProcFabric(Fabric):
    def __init__(self) -> None:
        self.nexus = InProcNexus()

    def endpoint_for(self, pub: crypto.PublicKey) -> Endpoint:
        return self.nexus.endpoint_for(pub)

    def attach(self, target: Participant | Postman) -> None:
        self.nexus.attach(target)


class TCPFabric(Fabric):
    def __init__(self) -> None:
        self._tunables: Tunables | None = None
        self._listeners: dict[bytes, TCPListener] = {}

    def set_tunables(self, tunables: Tunables) -> None:
        self._tunables = tunables

    def reserve(self, pub: crypto.PublicKey) -> None:
        assert self._tunables is not None
        key = bytes(pub)
        if key not in self._listeners:
            self._listeners[key] = TCPListener(
                self._tunables,
                listen_host="127.0.0.1",
                listen_port=0,
            )

    def endpoint_for(self, pub: crypto.PublicKey) -> Endpoint:
        self.reserve(pub)
        return Endpoint(self._listeners[bytes(pub)].bound_address)

    def attach(self, target: Participant | Postman) -> None:
        pub = target.me.public
        self.reserve(pub)
        listener = self._listeners[bytes(pub)]
        target.add_acceptor(listener)


class Cluster:
    def __init__(
        self,
        nodes: int = 3,
        mgmt: int = 1,
        ro: int = 0,
        rw: int = 0,
        tunables: Tunables | None = None,
        fabric: Fabric | None = None,
    ):
        self.tunables = tunables or TUNABLES
        self.fabric = fabric or InProcFabric()
        if isinstance(self.fabric, TCPFabric):
            self.fabric.set_tunables(self.tunables)
        self.anchor = crypto.Keypair.generate()

        node_keys = [crypto.Keypair.generate() for _ in range(nodes)]
        mgmt_keys = [crypto.Keypair.generate() for _ in range(mgmt)]
        ro_keys = [crypto.Keypair.generate() for _ in range(ro)]
        rw_keys = [crypto.Keypair.generate() for _ in range(rw)]

        self._genesis_bodies = self._genesis(node_keys, mgmt_keys, ro_keys, rw_keys)

        self.nodes: list[Node] = []
        for kp in node_keys:
            self._make_node(kp)
        for node in self.nodes:
            node.start()

        self.replicas: list[ReplicaNode] = []
        for kp in mgmt_keys:
            self._make_replica(kp)
        for rn in self.replicas:
            rn.start()

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
                (kp.public, (self.fabric.endpoint_for(kp.public),)) for kp in node_keys
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

    def _make_node(self, kp: crypto.Keypair) -> Node:
        store = self.provisioned()
        node = Node(kp, store, self.tunables)
        self.fabric.attach(node)
        self.nodes.append(node)
        return node

    def boot_replica(self, kp: crypto.Keypair) -> ReplicaNode:
        rn = self._make_replica(kp)
        rn.start()
        return rn

    def _make_replica(self, kp: crypto.Keypair) -> ReplicaNode:
        store = self.provisioned()
        rn = ReplicaNode(kp, store, self.tunables)
        self.fabric.attach(rn)
        self.replicas.append(rn)
        return rn

    def _boot_light_client(
        self,
        kp: crypto.Keypair,
        into: list[LightClient],
    ) -> LightClient:
        postman = Postman(kp, self.tunables, on_output=OutputQueue())
        self.fabric.attach(postman)
        lc = LightClient(me=kp, anchor=self.anchor.public, postman=postman)
        for node in self.nodes:
            lc.add_bootstrap_peer(
                node.me.public,
                (self.fabric.endpoint_for(node.me.public),),
            )
        lc.start()
        into.append(lc)
        return lc

    # -- forcing blocks (test acceleration) -----------------------------------

    def set_immediate(self, enabled: bool = True) -> None:
        for node in self.nodes:
            node.set_immediate(enabled)

    def force_block(self) -> None:
        self.set_immediate(True)

    # -- waiting for convergence --------------------------------------------

    def _default_timeout(self, blocks: int = 10) -> float:
        floor = 3 * self.tunables.block_time.as_seconds
        return max(floor, blocks * self.tunables.block_time.as_seconds)

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
            time.sleep(self.tunables.tick_interval.as_seconds)
        raise TimeoutError(f"predicate not satisfied within {t:.1f}s")

    def wait_settled(
        self,
        result: object,
        nodes: list[Node | ReplicaNode] | None = None,
    ) -> Settled:
        if not isinstance(result, Settled):
            raise TypeError(f"expected Settled, got {result!r}")
        settled = result
        check = nodes if nodes is not None else self.nodes
        self.wait(lambda _: all(n.store.has_settled(settled.op_hash) for n in check))
        return result

    # -- teardown -----------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        for lc in self.ro_clients + self.rw_clients:
            lc.stop()
        for rn in self.replicas:
            rn.stop()
        for node in self.nodes:
            node.stop()
