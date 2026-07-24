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
    "PROMISE": "0c765c942d9facea78b165e190b7042fafb14d557d85af6e01380b89b8652e33",
    "WATERMARK": "c7c4bdd75f1ba39b638eb9990e11a7308c1df54388346f49fa44dda3c4ea5fd8",
    "FRONTIER": "18d788a8f7db05544196a00879139b7c8197733e317ecf8b6db5083f7dc39738",
    "QC": "be1cc98ff485640b3bff9c35de523d2f2a209795a047be10a14c12e3264af7e0",
    "RECEIPT": "694d9669713112693c670f5e14e1f27355a98a526d1a258f9089e706c2a7508b",
    "SUMMARY": "4d8e7ebe7b3f2fc94514ba44684e9bdd69560e771946cd59bcad44a308a44c91",
    "DELTA": "88eee72066546fef3498c42ac81f1a869690ec2584495452f49a2e60f0583e7a",
    "REQ_submit": "ff7eaea8acfb087b2b8140dd453e40cc0093b04941eb4662dfebff2cbb722581",
    "REQ_prepare": "bfd627b7ba7860af3e590bd810755e68355902237291e66084de7d520d7edd50",
    "REQ_accept": "ee867f532d0377f9cdc989545cb619c845520506b12311398c27cececf2872fd",
    "REQ_roster_accept": "293b9469d9e9dada020525b29a9f1ddd0f69cdc07d6eb5e565cb7f835fe81b01",
    "REQ_frontier": "5c030af3337149f14473a78d626f5550229bd5ecf83a1743d56ce82e5e240faa",
    "REQ_watermark": "a8c55c102cde3fdd962b49bcf81e88c046cf71822836e5f63b7019c0c1f74493",
    "REQ_fetch": "000aab5f778d667aa72e0b598d359586f1093e43c1f1744745aa58e81ea6fa18",
    "REQ_getqc": "b5301216a79171bc89b5bff50d2da9300547fcbf68e4ea2e05796a0134e40901",
    "REQ_putqc": "564a75e060c47e7287e2421ae6c9e4b07ea5641543f0650ec9b1a80f8d95e7c4",
    "RESP_receipt": "1c93ab5507d286e9b0d41827691c46cf08f4624c5a927e39dc8bfa4692ba0ae3",
    "RESP_nack": "803792e20f152e9390f7a6f10412132b3629793ba682c9c853d31077da091f92",
    "RESP_rejected": "dca3c0be74b8cfe7c8d18cebf49a38a430866ce8f61af950868dfacf102007d8",
    "RESP_promise": "5ee776182977af5c2b8ecaff2b032786e41969bed16c395801f5f543136f6ef2",
    "RESP_watermark": "83bd7358542fc7125c781372ecb0a511ccb7988b9c3446e07a2e5a1795398fac",
    "RESP_frontier": "6ca22ad13ccb589c7fcb92567cad5e99b78708d9b847393809184a34855e35f6",
    "RESP_qc": "bd61e927c1e9faaac46eded4c254b1a3b63b9924cdc361385aa520653ebf96a8",
    "RESP_op": "8815741b64b60e517e44d473b1dbdc2fbdf58ad91fbb84693fa54843a29a8e20",
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
    op = A.CasOp.build(
        author_sk=sk,
        author_pub=pub,
        seq=0,
        prev=A.GENESIS_PREV,
        hlc=A.HLC(1000, 0),
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
