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

    def test_opt_out_marker_permitted_under_proposed_rule(self):
        # ethereum/EIPs#12605: an opted-out account keeps ordinary ECDSA
        # authorization, so the marker is eligible under the proposed clause.
        db = make_db(OPT_OUT_MARKER)
        result = eip8151.ecrecover_precompile(
            db, DIGEST, V, R, S, allow_eip8476_opt_out_marker=True)
        self.assertTrue(result.permitted)
        self.assertEqual(result.output, ADDR.rjust(32, b"\x00"))
        self.assertEqual(result.gas_used, 6100)

    def test_contract_code_rejected(self):
        db = make_db(b"\x60\x00\x60\x00\xf3")
        result = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertFalse(result.permitted)


class TestGas(unittest.TestCase):
    def test_failed_recovery_costs_base_only(self):
        db = make_db(b"")
        result = eip8151.ecrecover_precompile(db, DIGEST, V, 0, 0)
        self.assertEqual(result.gas_used, 3000)  # spec: base cost
        self.assertEqual(result.output, b"")

    def test_cold_then_warm(self):
        # EIP-8151 states the totals literally: 6100 cold, 3200 warm.
        db = make_db(b"")
        first = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertEqual(first.gas_used, 6100)
        self.assertIn(ADDR, db.accessed_addresses)

        second = eip8151.ecrecover_precompile(db, DIGEST, V, R, S)
        self.assertEqual(second.gas_used, 3200)

    def test_rejects_nonstandard_v(self):
        # Verified against mainnet: ecrecover returns empty output for any v
        # other than 27/28, including the 0/1 parity encoding.
        db = make_db(b"")
        for v in (0, 1, 26, 29, 255):
            result = eip8151.ecrecover_precompile(db, DIGEST, v, R, S)
            self.assertFalse(result.permitted, msg=f"v={v}")
            self.assertEqual(result.output, b"")
            self.assertEqual(result.gas_used, eip8151.BASE_GAS)

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
