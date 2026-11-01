from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import erc8010

DELEGATE = bytes.fromhex("aa" * 20)
ACCOUNT = bytes.fromhex("bb" * 20)
DIGEST = bytes.fromhex("cc" * 32)
INIT_TO = bytes.fromhex("dd" * 20)


def authorization_blob(delegate: bytes = DELEGATE) -> bytes:
    words = [
        (1).to_bytes(32, "big"),
        delegate.rjust(32, b"\x00"),
        (0).to_bytes(32, "big"),
        (0).to_bytes(32, "big"),
        (1).to_bytes(32, "big"),
        (2).to_bytes(32, "big"),
    ]
    return b"".join(words)


class StubEnv(erc8010.VerifierEnv):
    def __init__(self, code: bytes, valid: bool = True):
        self._code = code
        self._valid = valid
        self.calls = []

    def code(self, account: bytes) -> bytes:
        return self._code

    def is_valid_signature(self, account, digest, signature) -> bool:
        return self._valid

    def call(self, target, data, authorization) -> bool:
        self.calls.append((target, data, authorization))
        return True

    def erc6492_verify(self, account, digest, signature) -> bool:
        return True


class TestLayouts(unittest.TestCase):
    def test_magic_is_32_bytes(self):
        self.assertEqual(len(erc8010.MAGIC), 32)
        self.assertEqual(erc8010.MAGIC, b"\x80\x10" * 16)

    def test_spec_layouts_conflict(self):
        # Finding F-1: signer-side and verifier-side layouts disagree.
        self.assertTrue(erc8010.layouts_conflict())
        self.assertNotEqual(erc8010.LAYOUT_SIGNER, erc8010.LAYOUT_VERIFIER)


class TestCodec(unittest.TestCase):
    def test_roundtrip_signer_layout(self):
        auth = authorization_blob()
        wrapped = erc8010.wrap_signature(
            b"sig", auth, INIT_TO, b"init", layout=erc8010.LAYOUT_SIGNER)
        parsed = erc8010.parse_wrapped(wrapped, layout=erc8010.LAYOUT_SIGNER)
        self.assertEqual(parsed.signature, b"sig")
        self.assertEqual(parsed.authorization, auth)
        self.assertEqual(parsed.init_to, INIT_TO)
        self.assertEqual(parsed.init_data, b"init")
        self.assertEqual(parsed.delegated, DELEGATE)

    def test_roundtrip_verifier_layout(self):
        auth = authorization_blob()
        wrapped = erc8010.wrap_signature(
            b"sig", auth, INIT_TO, b"init", layout=erc8010.LAYOUT_VERIFIER)
        parsed = erc8010.parse_wrapped(wrapped, layout=erc8010.LAYOUT_VERIFIER)
        self.assertEqual(parsed.init_to, INIT_TO)
        self.assertEqual(parsed.init_data, b"init")

    def test_signer_wrapped_does_not_parse_as_verifier(self):
        auth = authorization_blob()
        wrapped = erc8010.wrap_signature(
            b"sig", auth, INIT_TO, b"init", layout=erc8010.LAYOUT_SIGNER)
        with self.assertRaises(erc8010.DecodeError):
            erc8010.parse_wrapped(wrapped, layout=erc8010.LAYOUT_VERIFIER)

    def test_rejects_unwrapped(self):
        with self.assertRaises(erc8010.DecodeError):
            erc8010.parse_wrapped(b"\x01\x02\x03" * 40)

    def test_rejects_truncated(self):
        wrapped = erc8010.wrap_signature(
            b"sig", authorization_blob(), INIT_TO, b"", layout=erc8010.LAYOUT_SIGNER)
        with self.assertRaises(erc8010.DecodeError):
            erc8010.parse_wrapped(wrapped[:-40])


class TestVerification(unittest.TestCase):
    def _wrapped(self) -> bytes:
        return erc8010.wrap_signature(
            b"sig", authorization_blob(), INIT_TO, b"init",
            layout=erc8010.LAYOUT_SIGNER)

    def test_plain_signature_falls_back(self):
        env = StubEnv(b"")
        self.assertTrue(erc8010.verify(b"plain", ACCOUNT, DIGEST, env))
        with self.assertRaises(erc8010.DecodeError):
            erc8010.verify(b"plain", ACCOUNT, DIGEST, env, allow_plain=False)

    def test_already_delegated_uses_1271(self):
        env = StubEnv(b"\xef\x01\x00" + DELEGATE)
        self.assertTrue(erc8010.verify(self._wrapped(), ACCOUNT, DIGEST, env))
        self.assertEqual(env.calls, [])

    def test_not_delegated_initialises_then_verifies(self):
        env = StubEnv(b"")
        self.assertTrue(erc8010.verify(self._wrapped(), ACCOUNT, DIGEST, env))
        self.assertEqual(len(env.calls), 1)
        self.assertEqual(env.calls[0][0], INIT_TO)

    def test_invalid_1271_with_delegation_falls_back_to_ecrecover(self):
        env = StubEnv(b"\xef\x01\x00" + DELEGATE, valid=False)
        self.assertFalse(erc8010.verify(self._wrapped(), ACCOUNT, DIGEST, env))


if __name__ == "__main__":
    unittest.main()
