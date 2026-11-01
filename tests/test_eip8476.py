from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import eip8476
from w7702.eip8476 import OptOutStatus, RejectReason, SetCodeTransaction
from w7702.markers import DELEGATION_PREFIX, OPT_OUT_MARKER

SENDER = bytes.fromhex("28" * 20)


def valid_tx() -> SetCodeTransaction:
    return SetCodeTransaction(sender=SENDER, destination=SENDER)


class TestForm(unittest.TestCase):
    def test_valid_form(self):
        self.assertIsNone(eip8476.validate_form(valid_tx()))

    def test_rejections(self):
        cases = {
            RejectReason.NON_EMPTY_AUTHORIZATION_LIST: SetCodeTransaction(
                sender=SENDER, destination=SENDER, authorization_list=(b"x",)),
            RejectReason.DESTINATION_NOT_SENDER: SetCodeTransaction(
                sender=SENDER, destination=bytes.fromhex("11" * 20)),
            RejectReason.NONZERO_VALUE: SetCodeTransaction(
                sender=SENDER, destination=SENDER, value=1),
            RejectReason.NON_EMPTY_DATA: SetCodeTransaction(
                sender=SENDER, destination=SENDER, data=b"\x00"),
            RejectReason.NON_EMPTY_ACCESS_LIST: SetCodeTransaction(
                sender=SENDER, destination=SENDER, access_list=((1,),)),
        }
        for expected, tx in cases.items():
            self.assertEqual(eip8476.validate_form(tx), expected)


class TestTransition(unittest.TestCase):
    def test_applies_to_plain_eoa(self):
        result = eip8476.apply_opt_out(b"", valid_tx())
        self.assertIs(result.status, OptOutStatus.APPLIED)
        self.assertEqual(result.new_code, OPT_OUT_MARKER)
        self.assertEqual(result.gas_used, eip8476.OPT_OUT_GAS)

    def test_idempotent(self):
        result = eip8476.apply_opt_out(OPT_OUT_MARKER, valid_tx())
        self.assertIs(result.status, OptOutStatus.ALREADY_OPTED_OUT)
        self.assertEqual(result.new_code, OPT_OUT_MARKER)

    def test_refuses_existing_delegation(self):
        result = eip8476.apply_opt_out(
            DELEGATION_PREFIX + bytes.fromhex("aa" * 20), valid_tx())
        self.assertIs(result.status, OptOutStatus.REJECTED)
        self.assertEqual(result.reason, RejectReason.ACCOUNT_HAS_CODE)

    def test_rejected_form_does_not_change_state(self):
        tx = SetCodeTransaction(sender=SENDER, destination=SENDER, value=1)
        result = eip8476.apply_opt_out(b"", tx)
        self.assertIs(result.status, OptOutStatus.REJECTED)
        self.assertEqual(result.new_code, b"")
        self.assertEqual(result.gas_used, 0)


class TestSemantics(unittest.TestCase):
    def test_authorizations_are_skipped(self):
        self.assertTrue(eip8476.authorization_eligible(b""))
        self.assertTrue(eip8476.authorization_eligible(
            DELEGATION_PREFIX + bytes.fromhex("aa" * 20)))
        self.assertFalse(eip8476.authorization_eligible(OPT_OUT_MARKER))

    def test_evm_sees_empty_but_rpc_sees_marker(self):
        self.assertEqual(eip8476.execution_code(OPT_OUT_MARKER), b"")
        self.assertEqual(eip8476.raw_code_for_rpc(OPT_OUT_MARKER), OPT_OUT_MARKER)

    def test_txpool_treats_as_plain_eoa(self):
        self.assertFalse(eip8476.txpool_pending_limit_applies(OPT_OUT_MARKER))
        self.assertTrue(eip8476.txpool_pending_limit_applies(
            DELEGATION_PREFIX + bytes.fromhex("aa" * 20)))


if __name__ == "__main__":
    unittest.main()
