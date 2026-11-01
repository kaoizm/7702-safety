import sys

from _bootstrap import SRC  # noqa: F401  (adds src/ to sys.path)

import unittest

from w7702.crypto import rlp, secp256k1
from w7702.crypto.keccak import keccak256
from w7702.authorization import Authorization


class TestKeccak(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc(self):
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_fox(self):
        self.assertEqual(
            keccak256(b"The quick brown fox jumps over the lazy dog").hex(),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        )

    def test_block_boundary(self):
        # 135, 136 and 137 bytes exercise the padding edge cases.
        for length in (135, 136, 137, 271, 272):
            digest = keccak256(b"\xab" * length)
            self.assertEqual(len(digest), 32)
            self.assertNotEqual(digest, bytes(32))


class TestSecp256k1(unittest.TestCase):
    def test_known_address(self):
        # Well-known: private key 1 -> 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        self.assertEqual(
            secp256k1.address(1).hex().lower(),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        )

    def test_sign_recover_roundtrip(self):
        keys = [1, 2, 3, 0xDEADBEEF, 0x1234567890ABCDEF]
        for key in keys:
            digest = keccak256(key.to_bytes(32, "big"))
            r, s, parity = secp256k1.sign(digest, key, 0xCAFEBABE + key)
            self.assertEqual(secp256k1.recover_address(digest, parity, r, s),
                             secp256k1.address(key))

    def test_low_s(self):
        digest = keccak256(b"low-s")
        _, s, _ = secp256k1.sign(digest, 7, 12345)
        self.assertLessEqual(s, secp256k1.N // 2)

    def test_invalid_signature(self):
        digest = keccak256(b"x")
        self.assertIsNone(secp256k1.recover(digest, 0, 0, 0))
        self.assertIsNone(secp256k1.recover(digest, 0, 1, 0))
        self.assertIsNone(secp256k1.recover(digest, 2, 1, 1))


class TestRlp(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(rlp.encode_int(0), b"\x80")
        self.assertEqual(rlp.encode_int(1), b"\x01")
        self.assertEqual(rlp.encode_int(127), b"\x7f")
        self.assertEqual(rlp.encode_int(128), b"\x81\x80")
        self.assertEqual(rlp.encode_bytes(b"dog"), b"\x83dog")
        self.assertEqual(rlp.encode_bytes(b""), b"\x80")
        self.assertEqual(rlp.encode_list([b"cat", b"dog"]),
                         b"\xc8\x83cat\x83dog")
        self.assertEqual(rlp.encode([b"cat", b"dog"]), b"\xc8\x83cat\x83dog")
        self.assertEqual(rlp.encode([]), b"\xc0")

    def test_encode_tuple(self):
        encoded = rlp.encode([1, bytes.fromhex("aa" * 20), 0])
        self.assertEqual(encoded[0], 0xC0 + len(encoded) - 1)
        self.assertEqual(encoded[1], 0x01)
        self.assertEqual(encoded[2], 0x94)  # 20-byte string
        self.assertEqual(encoded[-1], 0x80)  # zero integer

    def test_rejects_bool(self):
        with self.assertRaises(TypeError):
            rlp.encode(True)


class TestAuthorization(unittest.TestCase):
    def test_signing_hash_is_deterministic(self):
        auth = Authorization(chain_id=1, address=bytes.fromhex("11" * 20), nonce=0)
        self.assertEqual(auth.signing_hash(), auth.signing_hash())
        self.assertEqual(len(auth.signing_hash()), 32)

    def test_chain_id_zero_differs(self):
        a = Authorization(chain_id=0, address=bytes.fromhex("11" * 20), nonce=0)
        b = Authorization(chain_id=1, address=bytes.fromhex("11" * 20), nonce=0)
        self.assertNotEqual(a.signing_hash(), b.signing_hash())

    def test_sign_and_recover_authority(self):
        key = 0xBADCAFE
        auth = Authorization(chain_id=1, address=bytes.fromhex("22" * 20), nonce=7)
        signed = auth.sign(key, nonce=0xFEEDFACE)
        self.assertTrue(signed.is_signed)
        self.assertEqual(signed.authority(), secp256k1.address(key))


if __name__ == "__main__":
    unittest.main()
