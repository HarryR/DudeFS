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
    "PROMISE": "8ff9a6c9206e4e3e9aee30892c18a0dc35efd7200f957aa6879945caf8b0a181",
    "WATERMARK": "c7c4bdd75f1ba39b638eb9990e11a7308c1df54388346f49fa44dda3c4ea5fd8",
    "FRONTIER": "d645e99fb2777a3faf7a2dc4992a936a4b5912fe4d3a532f59c11185377d879f",
    "QC": "64e1f6a27d81d0d5eb9dda364892eeb35a01d2b260d636aeb2daf3738db361a0",
    "RECEIPT": "539d544211a27fb0f890816e8ba0736dda34f8fde9f2f6755ece01682b682e6f",
    "SUMMARY": "b65fdd1fe3776bd6f396e5d93733e8893cf290aa01520dbb7fb75cd67e9daf98",
    "DELTA": "456ac81b1eb2f7d9cb711a21c106b55568c95d3f335cd452dae1adca2828af06",
    "REQ_submit": "9d87371b7ca20bfa328976a20f6ff510200194677ad566140853d28b59f38173",
    "REQ_prepare": "bfd627b7ba7860af3e590bd810755e68355902237291e66084de7d520d7edd50",
    "REQ_accept": "fec7ac7c8efde7ce5b85f73f65569d93e671093845d1629459b6a278a3548041",
    "REQ_roster_accept": "7313f6dd18b959d4cf78aae11d5562e2f2c391b673d0ac6e54388beb1e2fd17b",
    "REQ_frontier": "5c030af3337149f14473a78d626f5550229bd5ecf83a1743d56ce82e5e240faa",
    "REQ_watermark": "a8c55c102cde3fdd962b49bcf81e88c046cf71822836e5f63b7019c0c1f74493",
    "REQ_fetch": "133190b8db9b226e3640b1b1bad7d1568ba29852f5e269c34ceda61d707d3a29",
    "REQ_getqc": "394486db5dc67f52a597e5b26fe154df2dddc3f743a2327469a4fe6ee885d4ec",
    "REQ_putqc": "356fa9377862d1ddd789f963227247584669b70c97ba50601408fc21dcea14dc",
    "RESP_receipt": "bb2d5b8def23e7999c38c23f56f1c499a2650e5d515cb72064a3c2c9f63261bc",
    "RESP_nack": "803792e20f152e9390f7a6f10412132b3629793ba682c9c853d31077da091f92",
    "RESP_rejected": "dca3c0be74b8cfe7c8d18cebf49a38a430866ce8f61af950868dfacf102007d8",
    "RESP_promise": "b13adf20cfad8a4af9ba4e7c4e52d9f234653033569cbca1af29c80bdedae232",
    "RESP_watermark": "83bd7358542fc7125c781372ecb0a511ccb7988b9c3446e07a2e5a1795398fac",
    "RESP_frontier": "13475796cfcd05da711a607e31bcaf62e065d187bec835433a8223312b89951a",
    "RESP_qc": "5cedf430b6a95a3ef7276efe70eff329fb7d7dc1452097f69a3b7adf54170a38",
    "RESP_op": "56268c176f413b74e02dd8c7937ab96507c8fb5aa2dd529a3f570237e06bb6da",
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
