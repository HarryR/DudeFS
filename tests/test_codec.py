# M0 — canonical bencode codec: roundtrip, injectivity, canonicity, rejection.
# FORMAL §1 (injective + canonical encodings are assumptions of every theorem).

import random
import unittest

from dudefs import codec


class TestCodecRoundtrip(unittest.TestCase):
    # bencode sequences decode to immutable tuples (see codec.Bencodable), so the
    # round-trip fixtures use tuples; encode() still accepts lists or tuples.
    VALUES = [
        0,
        1,
        -1,
        42,
        -42,
        255,
        256,
        2**64,
        b"",
        b"hello",
        bytes(range(256)),
        (),
        (1, b"a", (2, (3,))),
        {},
        {b"a": 1, b"bb": b"x"},
        {b"nested": {b"k": (1, 2, {b"z": b""})}},
    ]

    def test_roundtrip_and_idempotent(self):
        for v in self.VALUES:
            enc = codec.encode(v)
            self.assertEqual(codec.decode(enc), v)
            self.assertEqual(codec.encode(codec.decode(enc)), enc)  # canonical fixpoint

    def test_list_and_tuple_encode_identically(self):
        # a list encodes the same as the equivalent tuple; decode yields a tuple.
        self.assertEqual(codec.encode([1, b"a"]), codec.encode((1, b"a")))
        self.assertEqual(codec.decode(codec.encode([1, b"a"])), (1, b"a"))


class TestCanonicity(unittest.TestCase):
    def test_dict_keys_sorted(self):
        self.assertEqual(codec.encode({b"b": 1, b"a": 2}), b"d1:ai2e1:bi1ee")

    def test_int_minimal(self):
        self.assertEqual(codec.encode(0), b"i0e")
        self.assertEqual(codec.encode(-1), b"i-1e")

    def test_injective_distinct_values_distinct_bytes(self):
        rng = random.Random(1234)
        seen = {}
        for _ in range(5000):
            v = _rand_value(rng, depth=3)
            enc = codec.encode(v)
            # decode(encode(v)) == v guarantees injectivity; also no collisions
            self.assertEqual(codec.decode(enc), v)
            if enc in seen:
                self.assertEqual(seen[enc], v)
            seen[enc] = v


class TestRejection(unittest.TestCase):
    BAD = [
        b"i00e",
        b"i-0e",
        b"i01e",
        b"i-01e",  # non-minimal ints
        b"01:a",
        b"00:",  # non-minimal length
        b"d1:bi1e1:ai2ee",  # keys out of order
        b"d1:ai1e1:ai2ee",  # duplicate key
        b"i1ex",  # trailing garbage
        b"l",
        b"d",
        b"i1e"[:2],  # unterminated / truncated
        b"ie",
        b"i-e",  # missing digits
        b"5:ab",  # length longer than input
        b"di1ei2ee",  # non-bytes dict key
        b"",  # empty input
    ]

    def test_rejects_noncanonical_and_malformed(self):
        for b in self.BAD:
            with self.assertRaises(codec.CodecError, msg=repr(b)):
                codec.decode(b)

    def test_rejects_unencodable(self):
        for v in [True, False, 1.5, None, "str", {1: 2}]:
            with self.assertRaises(codec.CodecError):
                codec.encode(v)


def _rand_value(rng, depth):
    t = rng.randrange(4 if depth > 0 else 2)
    if t == 0:
        return rng.randint(-(10**6), 10**6)
    if t == 1:
        return bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 8)))
    if t == 2:
        return tuple(_rand_value(rng, depth - 1) for _ in range(rng.randrange(0, 4)))
    return {
        bytes([rng.randrange(97, 123)] * (i + 1)): _rand_value(rng, depth - 1)
        for i in range(rng.randrange(0, 4))
    }


if __name__ == "__main__":
    unittest.main()
