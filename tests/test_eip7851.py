from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import eip7851
from w7702.markers import (
    DELEGATION_PREFIX,
    ECDSA_DISABLED_PREFIX,
)

A = bytes.fromhex("aa" * 20)
B = bytes.fromhex("bb" * 20)
ZERO = bytes(20)


class TestSelfDelegate(unittest.TestCase):
    def test_from_plain_eoa_is_noop(self):
        result = eip7851.apply_self_delegate(b"", A)
        self.assertFalse(result.success)
        self.assertEqual(result.new_code, b"")
        self.assertEqual(result.gas_used, eip7851.SETSELFDELEGATE_GAS)
        self.assertEqual(result.reason, "not_delegated")

    def test_from_enabled_delegation_burns_ecdsa(self):
        result = eip7851.apply_self_delegate(DELEGATION_PREFIX + A, B)
        self.assertTrue(result.success)
        self.assertEqual(result.new_code, ECDSA_DISABLED_PREFIX + B)

    def test_redelegate_keeps_ecdsa_disabled(self):
        result = eip7851.apply_self_delegate(ECDSA_DISABLED_PREFIX + A, B)
        self.assertTrue(result.success)
        self.assertEqual(result.new_code, ECDSA_DISABLED_PREFIX + B)
        self.assertNotEqual(result.new_code[:3], DELEGATION_PREFIX)

    def test_zero_delegate_is_rejected(self):
        result = eip7851.apply_self_delegate(DELEGATION_PREFIX + A, ZERO)
        self.assertFalse(result.success)
        self.assertEqual(result.new_code, DELEGATION_PREFIX + A)
        self.assertEqual(result.reason, "zero_delegate")

    def test_static_context_halts(self):
        with self.assertRaises(eip7851.StaticContextError):
            eip7851.apply_self_delegate(DELEGATION_PREFIX + A, B, is_static=True)

    def test_irreversible(self):
        # Assert the exact bytes, not the model's own classifier.
        code = DELEGATION_PREFIX + A
        for delegate in (B, A, bytes.fromhex("cc" * 20)):
            step = eip7851.apply_self_delegate(code, delegate)
            self.assertTrue(step.success)
            self.assertEqual(step.new_code, ECDSA_DISABLED_PREFIX + delegate)
            self.assertNotEqual(step.new_code[:3], DELEGATION_PREFIX)
            code = step.new_code


class TestValidation(unittest.TestCase):
    def test_authorization_allowed(self):
        self.assertTrue(eip7851.authorization_allowed(b""))
        self.assertTrue(eip7851.authorization_allowed(DELEGATION_PREFIX + A))
        self.assertFalse(eip7851.authorization_allowed(ECDSA_DISABLED_PREFIX + A))

    def test_transaction_allowed(self):
        self.assertTrue(eip7851.transaction_allowed(b""))
        self.assertTrue(eip7851.transaction_allowed(DELEGATION_PREFIX + A))
        self.assertFalse(eip7851.transaction_allowed(ECDSA_DISABLED_PREFIX + A))

    def test_helpers(self):
        self.assertTrue(eip7851.is_ecdsa_disabled(ECDSA_DISABLED_PREFIX + A))
        self.assertFalse(eip7851.is_ecdsa_disabled(DELEGATION_PREFIX + A))
        self.assertTrue(eip7851.is_ecdsa_enabled_delegation(DELEGATION_PREFIX + A))
        self.assertFalse(eip7851.is_ecdsa_enabled_delegation(ECDSA_DISABLED_PREFIX + A))


if __name__ == "__main__":
    unittest.main()
