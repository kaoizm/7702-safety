from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import eip8151
from w7702.crypto import secp256k1
from w7702.crypto.keccak import keccak256
from w7702.markers import (
    DELEGATION_PREFIX,
    ECDSA_DISABLED_PREFIX,
    OPT_OUT_MARKER,
)

KEY = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
DIGEST = keccak256(b"7702-safety/eip8151")
R, S, PARITY = secp256k1.sign(DIGEST, KEY, 0xC0FFEE)
ADDR = secp256k1.address(KEY)
V = 27 + PARITY


def make_db(code: bytes) -> eip8151.AccountDB:
    return eip8151.AccountDB(raw_code={ADDR: code})


class TestECRecoverRestriction(unittest.TestCase):
    def test_empty_code_permitted(self):
        db = make_db(b"")
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertTrue(result.permitted)
        self.assertEqual(result.output, ADDR.rjust(32, b"\x00"))
        self.assertEqual(result.recovered, ADDR)

    def test_enabled_delegation_permitted(self):
        db = make_db(DELEGATION_PREFIX + bytes.fromhex("aa" * 20))
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertTrue(result.permitted)
        self.assertEqual(result.output, ADDR.rjust(32, b"\x00"))

    def test_ecdsa_disabled_rejected(self):
        db = make_db(ECDSA_DISABLED_PREFIX + bytes.fromhex("aa" * 20))
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertFalse(result.permitted)
        self.assertEqual(result.output, b"")

    def test_opt_out_marker_rejected(self):
        db = make_db(OPT_OUT_MARKER)
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertFalse(result.permitted)
        self.assertEqual(result.output, b"")

    def test_contract_code_rejected(self):
        db = make_db(b"\x60\x00\x60\x00\xf3")
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertFalse(result.permitted)


class TestGas(unittest.TestCase):
    def test_failed_recovery_costs_base_only(self):
        db = make_db(b"")
        result = eip8151.ecrecover_precompile(db, DIGEST, V, 0, 0)
        self.assertEqual(result.gas_used, eip8151.BASE_GAS)
        self.assertEqual(result.output, b"")

    def test_cold_then_warm(self):
        db = make_db(b"")
        first = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        expected_cold = eip8151.BASE_GAS + eip8151.COLD_ACCOUNT_ACCESS + eip8151.WARM_ACCESS
        self.assertEqual(first.gas_used, expected_cold)
        self.assertIn(ADDR, db.accessed_addresses)

        second = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        expected_warm = eip8151.BASE_GAS + eip8151.WARM_ACCESS + eip8151.WARM_ACCESS
        self.assertEqual(second.gas_used, expected_warm)

    def test_out_of_gas_at_base(self):
        db = make_db(b"")
        with self.assertRaises(eip8151.OutOfGas):
            eip8151.ecrecover_precompile(db, DIGEST, V, R, S, gas_limit=2999)

    def test_out_of_gas_at_code_check(self):
        db = make_db(b"")
        with self.assertRaises(eip8151.OutOfGas):
            eip8151.ecrecover_precompile(db, DIGEST, V, R, S, gas_limit=3001)


if __name__ == "__main__":
    unittest.main()
