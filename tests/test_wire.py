# M7 WP1 — the cluster wire (framing + request/response codec). Every variant must
# survive frame -> read_frame -> decode, and responses are exercised from a REAL
# node dispatch (not hand-built) so the codec covers what the daemon actually emits.

import unittest

from dudefs import artifacts as A
from dudefs import crypto as C
from dudefs import node as N
from dudefs import wire
from dudefs.acceptor import Acceptor
from dudefs.store import ChainStore
from tests._builders import World


def _slotted(w):
    return w.cas(
        0, b"k", A.VERSION_ABSENT, 0, [[A.Guard.ABSENT, b"k"]], [[A.Mutation.SET, b"k", b"v"]]
    )


def _qc(w, op):
    sks = [bytes([210 + i] * 32) for i in range(3)]
    pubs = [C.SIGNER.public(s) for s in sks]
    recs = [A.Receipt.issue(sks[i], pubs[i], op.op_hash, 0, A.Ballot(1, b"x"), 1) for i in range(3)]
    return A.QC.assemble(recs, 3, {p: i for i, p in enumerate(pubs)})


class TestFraming(unittest.TestCase):
    def test_frame_read_frame_over_a_chunked_stream(self):
        payloads = [b"", b"hi", bytes(1000), b"\x00\x01\x02"]
        stream = b"".join(wire.frame(p) for p in payloads)
        pos = 0

        def recv(n):  # a byte-at-a-time source stresses the re-assembly loop
            nonlocal pos
            chunk = stream[pos : pos + min(n, 1)]
            pos += len(chunk)
            return chunk

        self.assertEqual([wire.read_frame(recv) for _ in payloads], payloads)
        self.assertIsNone(wire.read_frame(recv))  # clean EOF at a frame boundary


class TestRequestCodec(unittest.TestCase):
    def test_all_requests_roundtrip(self):
        w = World(seed=1, n_clients=1)
        op = _slotted(w)
        assert op.slot_tag is not None
        b = A.Ballot(1, b"x")
        reqs = [
            N.SubmitReq(op),
            N.PrepareReq(op.slot_tag, b),
            N.AcceptReq(op.slot_tag, b, op),
            N.FrontierReq(),
            N.WatermarkReq(),
            N.FetchOpReq(op.op_hash),
            N.GetQCReq(op.op_hash),
            N.PutQCReq(_qc(w, op)),
        ]
        for req in reqs:
            msg = wire.read_frame(_bytesource(wire.frame(wire.encode_request(req))))
            assert msg is not None
            back = wire.decode_request(msg)
            # round-trip is byte-stable (idempotent re-encode) — the strongest check
            self.assertEqual(
                wire.encode_request(back), wire.encode_request(req), type(req).__name__
            )


class TestResponseCodec(unittest.TestCase):
    def test_all_responses_from_a_real_node_roundtrip(self):
        w = World(seed=2, n_clients=1)
        sk = bytes([200] * 32)
        nd = N.LocalNode(Acceptor(sk, C.SIGNER.public(sk), ChainStore(), 0, 1_000_000), lambda: 100)
        op = _slotted(w)
        blind = w.blind(0, [], [[A.Mutation.SET, b"j", b"w"]])
        assert op.slot_tag is not None

        responses = [
            N.dispatch(nd, N.SubmitReq(blind)),  # Receipt
            N.dispatch(nd, N.SubmitReq(op)),  # Rejected(NEEDS_BALLOT) — slotted via SUBMIT
            N.dispatch(nd, N.PrepareReq(op.slot_tag, A.Ballot(5, b"z"))),  # Promise
            N.dispatch(nd, N.AcceptReq(op.slot_tag, A.Ballot(3, b"y"), op)),  # Nack (promised 5)
            N.dispatch(nd, N.AcceptReq(op.slot_tag, A.Ballot(6, b"z"), op)),  # Receipt
            N.dispatch(nd, N.FrontierReq()),  # FrontierBundle
            N.dispatch(nd, N.WatermarkReq()),  # Watermark
            N.dispatch(nd, N.FetchOpReq(op.op_hash)),  # Op
            N.dispatch(nd, N.FetchOpReq(b"\x00" * 32)),  # None
            N.dispatch(nd, N.GetQCReq(op.op_hash)),  # None
            N.dispatch(nd, N.PutQCReq(_qc(w, op))),  # None
        ]
        seen = set()
        for resp in responses:
            msg = wire.read_frame(_bytesource(wire.frame(wire.encode_response(resp))))
            assert msg is not None
            back = wire.decode_response(msg)
            self.assertEqual(wire.encode_response(back), wire.encode_response(resp))
            seen.add(type(resp).__name__)
        # every response kind was actually exercised
        expected = {"Receipt", "Rejected", "Promise", "Nack"}
        expected |= {"FrontierBundle", "Watermark", "Op", "NoneType"}
        self.assertEqual(seen, expected)


def _bytesource(data):
    pos = 0

    def recv(n):
        nonlocal pos
        chunk = data[pos : pos + n]
        pos += len(chunk)
        return chunk

    return recv


if __name__ == "__main__":
    unittest.main()
