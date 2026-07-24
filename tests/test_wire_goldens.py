# Pre-refactor golden net (NOTES 57 item 1): BYTE goldens for every wire artifact
# that was previously roundtrip-only. Roundtrips stay green through byte drift; a
# pinned digest of the encoded bytes does NOT — a moved golden is a behavior change
# by definition (the refactor ground rule). Each fixture is built from fixed keys,
# so Ed25519's RFC-8032 determinism makes the bytes reproducible.
#
# We pin `h(encoded).hex()` (compact drift-detector) rather than the full hex; the
# construction below IS the reference. Regenerate deliberately (and review the diff)
# only when the wire format is intended to change.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import gossip, wire
from dudefs import node as N
from dudefs.acceptor import Nack, Rejected, RejectReason
from dudefs.store import ChainStore

GOLDENS = {
    "PROMISE": "c5bb451ea28f2d399dffc03db7e69d5528f94f836aed3498e53a92f3407bb2e0",
    "WATERMARK": "c7c4bdd75f1ba39b638eb9990e11a7308c1df54388346f49fa44dda3c4ea5fd8",
    "FRONTIER": "6a5ce4f1a32969dd0c90b8de8ec041b511a0190599d49982deee2d02008b4782",
    "QC": "29f2738a962d7bda31a8e12d92a237804cdfe5303c7ba914319255b8e6d07d02",
    "RECEIPT": "a74599e60223187f6833ca9422c0d96823f1d0dc49df4027cd1615beeea096d7",
    "SUMMARY": "ed27f5324949d1f73f6c3bbfee154d654648c811a285c54ad83b697ecad65945",
    "DELTA": "e391aa380aa11c694fe9c658199ae9bd24768d6fdc6cca49a6f1e14f90f5f345",
    "REQ_submit": "639ba1db1b9f407759a00094e81c23f74c0c0d6c4153550acc25da677ee53455",
    "REQ_prepare": "bfd627b7ba7860af3e590bd810755e68355902237291e66084de7d520d7edd50",
    "REQ_accept": "3edcf9c0a3473b321af41c665d197f298c92f09b304c581dd876878d43ce6722",
    "REQ_roster_accept": "556da9b666690a56cffc9732eb1ad62fbd88ce34099843379438dd9d41823388",
    "REQ_frontier": "5c030af3337149f14473a78d626f5550229bd5ecf83a1743d56ce82e5e240faa",
    "REQ_watermark": "a8c55c102cde3fdd962b49bcf81e88c046cf71822836e5f63b7019c0c1f74493",
    "REQ_fetch": "cdb690891a0d234aebf9e65f2595f6ab3f55478a3b85f1adf3ce247e09705471",
    "REQ_getqc": "79c69e70168ec84bca71609c83b109fc72633d041579e59fa4d18df991a04306",
    "REQ_putqc": "fc749a3404ee149b67949e9112c0366173e9c29ae3b222774879b4eff946570e",
    "RESP_receipt": "4074098b77be77306935469d0c4a4663449f57baa71ef7cda7ca623bcfd54fbc",
    "RESP_nack": "803792e20f152e9390f7a6f10412132b3629793ba682c9c853d31077da091f92",
    "RESP_rejected": "dca3c0be74b8cfe7c8d18cebf49a38a430866ce8f61af950868dfacf102007d8",
    "RESP_promise": "e053412196985f09a9b98b11b35920266572ddd3c9d4d19857b4a594bc80bcdb",
    "RESP_watermark": "83bd7358542fc7125c781372ecb0a511ccb7988b9c3446e07a2e5a1795398fac",
    "RESP_frontier": "3bc9d65eac9634e221d16ea7fa00c808a478ed0f16fab6b223ac129fe5655e60",
    "RESP_qc": "a87fb97c4824d2cf8936dabcab48cf89185d8259c86cad454faa7e991d4b0dec",
    "RESP_op": "830b37bcd8f46e9c4c7913f47a9d54b84ea95fbbf61f79bee82f7fb7c5b6b41c",
    "RESP_none": "321275551e3c42277d8c133b3831874ab193a68c1cc25a0df6e48996ee7b6465",
}


def _fixtures() -> dict[str, bytes]:
    """Every wire artifact + framed request/response, built from FIXED keys."""
    sk = bytes(range(32))
    pub = C.SIGNER.public(sk)
    bal = A.Ballot(3, b"pri")
    txn = A.Txn(
        (b"k", A.VERSION_ABSENT, 0), [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v"]]
    )
    tag = A.compute_slot_tag(bytes([9] * 32), b"k", A.VERSION_ABSENT, 0)
    op = A.Op.build_data(
        author_sk=sk,
        author_pub=pub,
        seq=0,
        prev=A.GENESIS_PREV,
        hlc=A.HLC(1000, 0),
        deps=[],
        authz=b"cert",
        keyepoch=0,
        data_key=bytes([1] * 32),
        txn_bytes=txn.encode(),
        slot_tag=tag,
    )
    heads = {pub: (0, op.op_hash)}
    promise = A.Promise.issue(sk, pub, tag, bal, A.Ballot(1, b"a"), op.op_hash, A.HLC(999, 0))
    wm = A.Watermark.issue(sk, pub, A.HLC(500, 0), 0, 3)
    fb = A.FrontierBundle.issue(sk, pub, heads, op.op_hash, 0, A.HLC(500, 0))
    recs = [
        A.Receipt.issue(
            bytes([200 + i] * 32), C.SIGNER.public(bytes([200 + i] * 32)), op.op_hash, 0, bal, i + 1
        )
        for i in range(3)
    ]
    qc = A.QC.assemble(recs, 3, {C.SIGNER.public(bytes([200 + i] * 32)): i for i in range(3)})

    st = ChainStore()
    with st.write_txn() as tx:
        tx.put_op_raw(op)
        tx.put_qc(qc)
        for r in recs:
            tx.put_receipt(r)
    empty = ChainStore()
    with empty.read_txn() as etx, st.read_txn() as tx:
        summ = gossip.Summary.of(tx, 0, None, b"", frozenset())
        delt = gossip.Delta.owed(tx, gossip.Summary.of(etx, 0, None, b"", frozenset()))
        delt = gossip.Delta(delt.ops, delt.receipts, delt.qcs, baseline=(op,))  # pin baseline field

    reqs = {
        "REQ_submit": N.SubmitReq(op),
        "REQ_prepare": N.PrepareReq(tag, bal),
        "REQ_accept": N.AcceptReq(tag, bal, op),
        "REQ_roster_accept": N.RosterAcceptReq(tag, bal, op, heads, 1),
        "REQ_frontier": N.FrontierReq(),
        "REQ_watermark": N.WatermarkReq(),
        "REQ_fetch": N.FetchOpReq(op.op_hash),
        "REQ_getqc": N.GetQCReq(op.op_hash),
        "REQ_putqc": N.PutQCReq(qc),
    }
    resps = {
        "RESP_receipt": recs[0],
        "RESP_nack": Nack(bal),
        "RESP_rejected": Rejected(RejectReason.BELOW_FLOOR),
        "RESP_promise": promise,
        "RESP_watermark": wm,
        "RESP_frontier": fb,
        "RESP_qc": qc,
        "RESP_op": op,
        "RESP_none": None,
    }
    out = {
        "PROMISE": promise.encode(),
        "WATERMARK": wm.encode(),
        "FRONTIER": fb.encode(),
        "QC": qc.encode(),
        "RECEIPT": recs[0].encode(),
        "SUMMARY": summ.encode(),
        "DELTA": delt.encode(),
    }
    out.update({k: wire.frame(wire.encode_request(r)) for k, r in reqs.items()})
    out.update({k: wire.frame(wire.encode_response(r)) for k, r in resps.items()})
    return out


class TestWireGoldens(unittest.TestCase):
    def test_every_wire_artifact_is_byte_pinned(self):
        fx = _fixtures()
        self.assertEqual(set(fx), set(GOLDENS), "fixture/golden key sets must match")
        for name, encoded in fx.items():
            self.assertEqual(C.h(encoded).hex(), GOLDENS[name], f"{name} bytes drifted")


class TestJsonRpcContract(unittest.TestCase):
    """One example request per worker verb + its response SHAPE (NOTES 57 item 1).
    Pins the JSON-RPC contract: the accepted params and the returned key-set for
    each verb. No cluster needed — reads fold locally, writes return a ticket."""

    def _daemon(self):
        from dudefs.client import ClientDaemon
        from tests._builders import World, unix_eps

        w = World(seed=1, n_clients=1)
        return ClientDaemon(
            w.clients[0].sk,
            w.clients[0].pub,
            roster=[C.SIGNER.public(bytes([1] * 32))],
            roster_addrs=unix_eps(["/nonexistent.sock"]),
            manager_pub=w.mgr_pub,
            control_ops=w.control_ops,
            epoch=0,
        )

    def test_each_verb_request_example_yields_the_documented_shape(self):
        from dudefs.workerapi import WorkerAPI

        api = WorkerAPI(self._daemon())
        # (method, example params, required result keys)
        cases = [
            ("TXN", {"slot": None, "mutations": [{"set": "k", "value": "v"}]}, {"op"}),
            ("PUT", {"path": "k", "value": "v"}, {"op"}),
            (
                "CAS",
                {"path": "k", "expect": "absent", "mutations": [{"set": "k", "value": "v"}]},
                {"op"},
            ),
            (
                "GET",
                {"path": "k", "level": "local"},
                {"value", "version", "attempt", "present", "as_of", "tier"},
            ),
            ("LIST", {"prefix": ""}, {"keys"}),
            ("INSPECT", {"path": "k"}, {"final", "provisional", "may_flip", "pending"}),
            ("STATUS", {"op": "00" * 32}, {"phase", "may_flip"}),
        ]
        for method, params, required in cases:
            result = api.handle(method, params)
            assert isinstance(result, dict), method
            self.assertTrue(required <= set(result), f"{method}: missing {required - set(result)}")
        api.d.close()


if __name__ == "__main__":
    unittest.main()
