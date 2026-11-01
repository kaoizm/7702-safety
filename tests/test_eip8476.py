from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import eip8476
from w7702.eip8476 import OptOutStatus, RejectReason, SetCodeTransaction
from w7702.markers import DELEGATION_PREFIX, ECDSA_DISABLED_PREFIX, OPT_OUT_MARKER

SENDER = bytes.fromhex("28" * 20)
OTHER = bytes.fromhex("11" * 20)


def valid_tx(**overrides) -> SetCodeTransaction:
    fields = dict(sender=SENDER, destination=SENDER)
    fields.update(overrides)
    return SetCodeTransaction(**fields)


class TestForm(unittest.TestCase):
    def test_valid_form(self):
        self.assertIsNone(eip8476.validate_form(valid_tx()))

    def test_rejections(self):
        cases = {
            RejectReason.NON_EMPTY_AUTHORIZATION_LIST: valid_tx(
                authorization_list=(b"x",)),
            RejectReason.DESTINATION_NOT_SENDER: valid_tx(destination=OTHER),
            RejectReason.NONZERO_VALUE: valid_tx(value=1),
            RejectReason.NON_EMPTY_DATA: valid_tx(data=b"\x00"),
            RejectReason.NON_EMPTY_ACCESS_LIST: valid_tx(access_list=((1,),)),
        }
        for expected, tx in cases.items():
            self.assertEqual(eip8476.validate_form(tx), expected)


class TestTransactionValidity(unittest.TestCase):
    def test_gas_limit_below_minimum_is_invalid(self):
        tx = valid_tx(gas_limit=eip8476.OPT_OUT_GAS - 1)
        self.assertEqual(
            eip8476.validate_transaction(tx), RejectReason.GAS_LIMIT_TOO_LOW)

    def test_chain_id_must_match(self):
        tx = valid_tx(chain_id=1)
        self.assertEqual(
            eip8476.validate_transaction(tx, current_chain_id=5),
            RejectReason.CHAIN_ID_MISMATCH,
        )
        self.assertIsNone(eip8476.validate_transaction(tx, current_chain_id=1))

    def test_zero_chain_id_does_not_bypass_outer_rule(self):
        # The chain_id = 0 exception is for authorization tuples, not the
        # outer transaction.
        tx = valid_tx(chain_id=0)
        self.assertEqual(
            eip8476.validate_transaction(tx, current_chain_id=5),
            RejectReason.CHAIN_ID_MISMATCH,
        )

    def test_nonce_bounds(self):
        self.assertEqual(
            eip8476.validate_transaction(valid_tx(nonce=2**64)),
            RejectReason.NONCE_OUT_OF_RANGE,
        )
        self.assertIsNone(eip8476.validate_transaction(valid_tx(nonce=2**64 - 1)))


class TestTransition(unittest.TestCase):
    def test_applies_to_plain_eoa(self):
        result = eip8476.apply_opt_out(b"", valid_tx())
        self.assertIs(result.status, OptOutStatus.APPLIED)
        self.assertEqual(result.new_code, OPT_OUT_MARKER)
        self.assertEqual(result.gas_used, eip8476.OPT_OUT_GAS)
        self.assertFalse(result.already_marked)

    def test_repeat_is_valid_and_consumes_gas(self):
        # EIP-8476 Test Cases: code M, gas limit 40000 ->
        # gas used 33500, unused 6500 returned.
        tx = valid_tx(gas_limit=40000)
        result = eip8476.apply_opt_out(OPT_OUT_MARKER, tx)
        self.assertIs(result.status, OptOutStatus.APPLIED)
        self.assertTrue(result.already_marked)
        self.assertEqual(result.new_code, OPT_OUT_MARKER)
        self.assertEqual(result.gas_used, 33500)
        self.assertEqual(tx.gas_limit - result.gas_used, 6500)

    def test_replaces_existing_delegation(self):
        result = eip8476.apply_opt_out(
            DELEGATION_PREFIX + OTHER, valid_tx())
        self.assertIs(result.status, OptOutStatus.APPLIED)
        self.assertEqual(result.new_code, OPT_OUT_MARKER)

    def test_ecdsa_disabled_sender_rejected(self):
        result = eip8476.apply_opt_out(
            ECDSA_DISABLED_PREFIX + OTHER, valid_tx())
        self.assertIs(result.status, OptOutStatus.REJECTED)
        self.assertEqual(result.reason, RejectReason.ECDSA_DISABLED_SENDER)

    def test_rejected_form_does_not_change_state(self):
        result = eip8476.apply_opt_out(b"", valid_tx(value=1))
        self.assertIs(result.status, OptOutStatus.REJECTED)
        self.assertEqual(result.new_code, b"")
        self.assertEqual(result.gas_used, 0)


class TestSemantics(unittest.TestCase):
    def test_authorizations_are_skipped(self):
        self.assertTrue(eip8476.authorization_eligible(b""))
        self.assertTrue(eip8476.authorization_eligible(
            DELEGATION_PREFIX + OTHER))
        self.assertFalse(eip8476.authorization_eligible(OPT_OUT_MARKER))

    def test_evm_sees_empty_but_rpc_sees_marker(self):
        self.assertEqual(eip8476.execution_code(OPT_OUT_MARKER), b"")
        self.assertEqual(eip8476.raw_code_for_rpc(OPT_OUT_MARKER), OPT_OUT_MARKER)

    def test_txpool_treats_as_plain_eoa(self):
        self.assertFalse(eip8476.txpool_pending_limit_applies(OPT_OUT_MARKER))
        self.assertTrue(eip8476.txpool_pending_limit_applies(
            DELEGATION_PREFIX + OTHER))


if __name__ == "__main__":
    unittest.main()
