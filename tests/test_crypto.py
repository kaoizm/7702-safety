from _bootstrap import SRC  # noqa: F401

import unittest
from dataclasses import replace

from w7702.authorization import Authorization, is_valid_authority, validate
from w7702.crypto import rlp, secp256k1
from w7702.crypto.keccak import keccak256


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
        # Pinned digests around the 136-byte rate boundary. Length-only
        # assertions would pass with a broken padding rule; these would not.
        expected = {
            55: "171330308055b8916af320941e2124a34c9c428d8860b603f51e989522b4648a",
            56: "811aefaa9109cb13958f9ed814ed54293a62572f99c04c78daa1b4516ff416d0",
            135: "932fedc0e854cc4d32eec69e896c7449570052b3aaceacff7b13745325e4cf47",
            136: "302db73a4c8cc8ecc9004fec3a6525d9d6a2dd4b098b1bf62d1b897acff18c9d",
            137: "0235d14cb2563be9d300a26aa4dd02e37e51b802b1b204691db2de6a329d7948",
            271: "2f5aefa4b9b8599d9e5e36ee40b60685b156dd004ef0dd01a7abbe6360bb7914",
            272: "0245c297e7ae739cbe32c757a55bdb3064c9e0fdf25941d9496ac21e5efeed35",
        }
        for length, digest in expected.items():
            with self.subTest(length=length):
                self.assertEqual(keccak256(b"\xab" * length).hex(), digest)


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

    def test_invalid_private_key(self):
        digest = keccak256(b"key-range")
        for key in (0, secp256k1.N, -1, secp256k1.N + 5, True):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    secp256k1.sign(digest, key, 12345)
                with self.assertRaises(ValueError):
                    secp256k1.public_key(key)

    def test_eip155_known_signature(self):
        # EIP-155 example: chain 1, v = 37 (parity 0), key 0x4646...46.
        digest = bytes.fromhex(
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        r = 18515461264373351373200002665853028612451056578545711640558177340181847433846
        s = 46948507304638947509940763649030358759909902576025900602547168820602576006531
        recovered = secp256k1.recover_address(digest, 0, r, s)
        self.assertEqual(
            recovered.hex().lower(), "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")


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

    def test_long_form(self):
        # 55 bytes uses the short form; 56+ switches to a length byte.
        self.assertEqual(rlp.encode_bytes(b"a" * 55), b"\xb7" + b"a" * 55)
        self.assertEqual(rlp.encode_bytes(b"a" * 56), b"\xb8\x38" + b"a" * 56)
        self.assertEqual(rlp.encode_bytes(b"a" * 57), b"\xb8\x39" + b"a" * 57)
        self.assertEqual(rlp.encode_list([]), b"\xc0")
        self.assertEqual(
            rlp.encode_list([b"a" * 56]), b"\xf8\x3a" + rlp.encode_bytes(b"a" * 56))

    def test_rejects_bool(self):
        with self.assertRaises(TypeError):
            rlp.encode(True)
        with self.assertRaises(TypeError):
            rlp.encode_int(True)

    def test_large_integer(self):
        encoded = rlp.encode_int(2**256)
        self.assertEqual(encoded[0], 0xA1)  # 33-byte string, short form
        self.assertEqual(len(encoded), 34)


class TestAuthorization(unittest.TestCase):
    def test_signing_hash_is_deterministic(self):
        auth = Authorization(chain_id=1, address=bytes.fromhex("11" * 20), nonce=0)
        self.assertEqual(auth.signing_hash(), auth.signing_hash())
        self.assertEqual(len(auth.signing_hash()), 32)

    def test_chain_id_zero_differs(self):
        a = Authorization(chain_id=0, address=bytes.fromhex("11" * 20), nonce=0)
        b = Authorization(chain_id=1, address=bytes.fromhex("11" * 20), nonce=0)
        self.assertNotEqual(a.signing_hash(), b.signing_hash())

    def test_known_hashes(self):
        # Cross-checked against viem's published authorization-hashing examples.
        cases = [
            (1, "0xbe95c3f554e9fc85ec51be69a3d807a0d55bcf2c", 40,
             "0x5919da563810a99caf657d42bd10905adbd28b3b89b8a4577efa471e5e4b3914"),
            (69, "0xfba3912ca04dd458c843e2ee08967fc04f3579c2", 420,
             "0x9aeacccc1b8571dfc4fb4ba734dbde6e94d6c0188484413585144a755c359aac"),
            (0, "0xbe95c3f554e9fc85ec51be69a3d807a0d55bcf2c", 0,
             "0x70f22b957bc18cbaa757a12cc3e5fa5268b98b24afe15a35a76e6874748a8bfa"),
        ]
        for chain_id, address, nonce, expected in cases:
            with self.subTest(chain_id=chain_id):
                auth = Authorization(
                    chain_id=chain_id, address=bytes.fromhex(address[2:]), nonce=nonce)
                self.assertEqual("0x" + auth.signing_hash().hex(), expected)

    def test_sign_and_recover_authority(self):
        key = 0xBADCAFE
        auth = Authorization(chain_id=1, address=bytes.fromhex("22" * 20), nonce=7)
        signed = auth.sign(key, k=0xFEEDFACE)
        self.assertTrue(signed.is_signed)
        self.assertEqual(signed.authority(), secp256k1.address(key))


class TestAuthorizationValidation(unittest.TestCase):
    def _signed(self, **overrides) -> Authorization:
        auth = Authorization(chain_id=1, address=bytes.fromhex("22" * 20), nonce=0)
        signed = auth.sign(0xBADCAFE, k=0xFEEDFACE)
        return replace(signed, **overrides) if overrides else signed

    def test_valid_tuple_passes(self):
        self.assertEqual(validate(self._signed()), [])

    def test_chain_id_zero_is_chain_agnostic(self):
        signed = Authorization(
            chain_id=0, address=bytes.fromhex("22" * 20), nonce=0
        ).sign(0xBADCAFE, k=0xFEEDFACE)
        self.assertEqual(validate(signed, current_chain_id=5), [])

    def test_chain_id_mismatch(self):
        self.assertIn("chain_id mismatch", validate(self._signed(), current_chain_id=5))

    def test_nonce_boundary(self):
        # EIP-7702 step 2: nonce < 2**64 - 1, so 2**64 - 1 is the first invalid.
        self.assertIn(
            "nonce out of range", validate(self._signed(nonce=2**64 - 1)))
        self.assertEqual(validate(self._signed(nonce=2**64 - 2)), [])

    def test_high_s_rejected(self):
        signed = self._signed()
        self.assertIn(
            "high-s signature (EIP-2)",
            validate(self._signed(s=secp256k1.N - signed.s,
                                  y_parity=signed.y_parity ^ 1)),
        )

    def test_unrecoverable_authority(self):
        # r = 5 is in range but x = 5 is not on secp256k1, so a conforming
        # client skips the tuple.
        auth = Authorization(
            chain_id=1, address=bytes.fromhex("22" * 20), nonce=0, r=5, s=1)
        self.assertIn("authority unrecoverable", validate(auth))

    def test_authority_zero_rule(self):
        self.assertTrue(is_valid_authority(bytes.fromhex("11" * 20)))
        self.assertFalse(is_valid_authority(bytes(20)))


if __name__ == "__main__":
    unittest.main()
