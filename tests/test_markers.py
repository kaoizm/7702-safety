from _bootstrap import SRC  # noqa: F401

import unittest

from w7702 import markers
from w7702.markers import CodeKind

DELEGATE = bytes.fromhex("aa" * 20)
OTHER_DELEGATE = bytes.fromhex("bb" * 20)


class TestClassify(unittest.TestCase):
    def test_empty(self):
        self.assertIs(markers.classify(b""), CodeKind.EMPTY)

    def test_delegation(self):
        code = b"\xef\x01\x00" + DELEGATE
        self.assertIs(markers.classify(code), CodeKind.DELEGATION)
        self.assertEqual(markers.delegate_of(code), DELEGATE)

    def test_ecdsa_disabled(self):
        code = b"\xef\x01\x01" + DELEGATE
        self.assertIs(markers.classify(code), CodeKind.ECDSA_DISABLED)
        self.assertEqual(markers.delegate_of(code), DELEGATE)

    def test_opt_out(self):
        self.assertIs(markers.classify(b"\xef\x02\x00"), CodeKind.OPT_OUT)
        self.assertIsNone(markers.delegate_of(b"\xef\x02\x00"))

    def test_other(self):
        self.assertIs(markers.classify(b"\x60\x00"), CodeKind.OTHER)
        self.assertIs(markers.classify(b"\xef\x01\x00" + DELEGATE + b"\x00"),
                      CodeKind.OTHER)

    def test_indicators(self):
        self.assertEqual(markers.delegation_indicator(DELEGATE),
                         b"\xef\x01\x00" + DELEGATE)
        self.assertEqual(markers.ecdsa_disabled_indicator(DELEGATE),
                         b"\xef\x01\x01" + DELEGATE)
        with self.assertRaises(ValueError):
            markers.delegation_indicator(b"\x01")


class TestEip8151Predicate(unittest.TestCase):
    def test_permits_empty_and_enabled_delegation_only(self):
        self.assertTrue(markers.is_eip7702_delegated(b""))
        self.assertTrue(markers.is_eip7702_delegated(b"\xef\x01\x00" + DELEGATE))
        self.assertFalse(markers.is_eip7702_delegated(b"\xef\x01\x01" + DELEGATE))
        self.assertFalse(markers.is_eip7702_delegated(b"\xef\x02\x00"))
        self.assertFalse(markers.is_eip7702_delegated(b"\x60"))


class TestProposedOptOutEligibility(unittest.TestCase):
    def test_marker_eligible_only_under_proposed_rule(self):
        self.assertFalse(markers.is_permitted_ecrecover(b"\xef\x02\x00"))
        self.assertTrue(
            markers.is_permitted_ecrecover(b"\xef\x02\x00", opt_out_eligible=True))
        self.assertTrue(markers.is_permitted_ecrecover(b""))
        self.assertFalse(
            markers.is_permitted_ecrecover(b"\xef\x01\x01" + DELEGATE))


class TestEip8476Visibility(unittest.TestCase):
    def test_opted_out_executes_as_empty(self):
        self.assertEqual(markers.evm_visible_code(b"\xef\x02\x00"), b"")
        self.assertEqual(markers.evm_visible_code(b""), b"")
        self.assertEqual(markers.evm_visible_code(b"\xef\x01\x00" + DELEGATE),
                         b"\xef\x01\x00" + DELEGATE)


if __name__ == "__main__":
    unittest.main()
