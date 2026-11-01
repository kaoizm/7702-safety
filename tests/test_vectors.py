"""Replay vectors/conformance.json through the models.

This is the test that makes the published artifact load-bearing: every number
in the JSON is recomputed from the model and compared. A model bug that reaches
the generator now fails the suite instead of shipping confidently-wrong
vectors.
"""

from _bootstrap import SRC  # noqa: F401

import json
import pathlib
import unittest

from w7702 import eip7851, eip8151, eip8476, erc8010, markers
from w7702.authorization import Authorization
from w7702.crypto import secp256k1
from w7702.crypto.keccak import keccak256
from w7702.eip8476 import SetCodeTransaction

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "conformance.json"


def _bytes(value: str | None) -> bytes:
    if value is None:
        return b""
    return bytes.fromhex(value[2:])


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


class TestConformanceVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_meta(self) -> None:
        self.assertEqual(self.doc["meta"]["format"], "conformance-vectors/v1")
        for section in (
            "keccak256", "secp256k1", "authorization", "markers",
            "eip7851", "eip8151", "eip8151_proposed", "eip8476", "erc8010",
        ):
            with self.subTest(section=section):
                self.assertIn(section, self.doc)
                self.assertGreater(len(self.doc[section]), 0)

    def test_keccak256(self) -> None:
        for vector in self.doc["keccak256"]:
            with self.subTest(input=vector["input"]):
                self.assertEqual(
                    _hex(keccak256(_bytes(vector["input"]))), vector["digest"])

    def test_secp256k1(self) -> None:
        for vector in self.doc["secp256k1"]:
            with self.subTest(key=vector["private_key"]):
                digest = _bytes(vector["digest"])
                key = int(vector["private_key"], 16)
                r, s, parity = secp256k1.sign(digest, key, int(vector["nonce"], 16))
                self.assertEqual(r, int(vector["r"], 16))
                self.assertEqual(s, int(vector["s"], 16))
                self.assertEqual(parity, vector["y_parity"])
                self.assertEqual(_hex(secp256k1.address(key)), vector["signer"])
                self.assertEqual(
                    _hex(secp256k1.recover_address(digest, parity, r, s)),
                    vector["recovered"],
                )

    def test_authorization(self) -> None:
        for vector in self.doc["authorization"]:
            with self.subTest(chain_id=vector["chain_id"]):
                auth = Authorization(
                    chain_id=vector["chain_id"],
                    address=_bytes(vector["delegate"]),
                    nonce=vector["nonce"],
                )
                self.assertEqual(_hex(auth.signing_hash()), vector["signing_hash"])
                signed = Authorization(
                    chain_id=vector["chain_id"],
                    address=_bytes(vector["delegate"]),
                    nonce=vector["nonce"],
                    y_parity=vector["y_parity"],
                    r=int(vector["r"], 16),
                    s=int(vector["s"], 16),
                )
                self.assertEqual(_hex(signed.authority()), vector["authority"])

    def test_markers(self) -> None:
        for vector in self.doc["markers"]:
            with self.subTest(name=vector["name"]):
                code = _bytes(vector["code"])
                self.assertEqual(markers.classify(code).value, vector["kind"])
                delegate = markers.delegate_of(code)
                self.assertEqual(
                    None if delegate is None else _hex(delegate), vector["delegate"])
                self.assertEqual(
                    _hex(markers.evm_visible_code(code)),
                    vector["evm_visible_code"],
                )
                self.assertEqual(
                    markers.is_eip7702_delegated(code),
                    vector["eip8151_permitted"],
                )

    def test_eip7851(self) -> None:
        for vector in self.doc["eip7851"]:
            with self.subTest(label=vector["label"]):
                result = eip7851.apply_self_delegate(
                    _bytes(vector["input_code"]), _bytes(vector["delegate"]))
                self.assertEqual(result.success, vector["success"])
                self.assertEqual(_hex(result.new_code), vector["new_code"])
                self.assertEqual(result.gas_used, vector["gas_used"])
                self.assertEqual(result.reason, vector["reason"])

    def test_eip8151(self) -> None:
        for vector in self.doc["eip8151"]:
            with self.subTest(code=vector["account_code"]):
                db = eip8151.AccountDB(
                    raw_code={_bytes(vector["signer"]): _bytes(vector["account_code"])}
                )
                arguments = (db, _bytes(vector["digest"]), vector["v"],
                             int(vector["r"], 16), int(vector["s"], 16))
                cold = eip8151.ecrecover_precompile(*arguments)
                warm = eip8151.ecrecover_precompile(*arguments)
                self.assertEqual(_hex(cold.output), vector["output"])
                self.assertEqual(cold.permitted, vector["permitted"])
                self.assertEqual(cold.gas_used, vector["gas_cold"])
                self.assertEqual(warm.gas_used, vector["gas_warm"])

    def test_eip8151_proposed(self) -> None:
        for vector in self.doc["eip8151_proposed"]:
            with self.subTest(name=vector["name"]):
                db = eip8151.AccountDB(
                    raw_code={_bytes(vector["signer"]): _bytes(vector["account_code"])}
                )
                result = eip8151.ecrecover_precompile(
                    db, _bytes(vector["digest"]), vector["v"],
                    int(vector["r"], 16), int(vector["s"], 16),
                    opt_out_eligible=True,
                )
                self.assertEqual(_hex(result.output), vector["output"])
                self.assertEqual(result.permitted, vector["permitted"])
                self.assertEqual(result.gas_used, vector["gas_used"])

    def test_eip8476(self) -> None:
        for vector in self.doc["eip8476"]:
            with self.subTest(case=vector["case"]):
                raw = vector["tx"]
                tx = SetCodeTransaction(
                    sender=_bytes(raw["sender"]),
                    destination=_bytes(raw["destination"]),
                    value=raw["value"],
                    data=_bytes(raw["data"]),
                    access_list=tuple(None for _ in range(raw["access_list_length"])),
                    authorization_list=tuple(
                        None for _ in range(raw["authorization_list_length"])),
                    chain_id=raw["chain_id"],
                    gas_limit=raw["gas_limit"],
                    nonce=raw["nonce"],
                )
                result = eip8476.apply_opt_out(
                    _bytes(vector["input_code"]),
                    tx,
                    current_chain_id=vector["current_chain_id"],
                )
                self.assertEqual(result.status.value, vector["status"])
                self.assertEqual(
                    None if result.reason is None else result.reason.value,
                    vector["reason"],
                )
                self.assertEqual(_hex(result.new_code), vector["new_code"])
                self.assertEqual(result.gas_used, vector["gas_used"])
                self.assertEqual(result.already_marked, vector["already_marked"])

    def test_erc8010(self) -> None:
        for vector in self.doc["erc8010"]:
            with self.subTest(layout=vector["layout"]):
                parsed = erc8010.parse_wrapped(
                    _bytes(vector["wrapped"]), layout=erc8010.LAYOUT_SIGNER)
                self.assertEqual(_hex(parsed.signature), vector["signature"])
                self.assertEqual(_hex(parsed.init_to), vector["init_to"])
                self.assertEqual(_hex(parsed.init_data), vector["init_data"])
                self.assertEqual(_hex(parsed.delegated), vector["delegated"])
                self.assertEqual(
                    erc8010.layouts_conflict(), vector["layouts_conflict"])


if __name__ == "__main__":
    unittest.main()
