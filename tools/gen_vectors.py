"""Generate portable JSON conformance vectors from the executable reference.

Run:  python tools/gen_vectors.py
Output: vectors/conformance.json
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from w7702 import eip7851, eip8151, eip8476, erc8010, markers  # noqa: E402
from w7702.authorization import Authorization  # noqa: E402
from w7702.crypto import secp256k1  # noqa: E402
from w7702.crypto.keccak import keccak256  # noqa: E402
from w7702.eip8476 import SetCodeTransaction  # noqa: E402
from w7702.markers import (  # noqa: E402
    DELEGATION_PREFIX,
    ECDSA_DISABLED_PREFIX,
    OPT_OUT_MARKER,
)

KEY_A = 0x1111111111111111111111111111111111111111111111111111111111111111
KEY_B = 0x2222222222222222222222222222222222222222222222222222222222222222
DELEGATE_A = bytes.fromhex("aa" * 20)
DELEGATE_B = bytes.fromhex("bb" * 20)
DIGEST = keccak256(b"7702-safety/vector")


def hx(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return value


def build() -> dict:
    doc: dict = {
        "meta": {
            "suite": "7702-safety",
            "version": "0.1.0",
            "format": "conformance-vectors/v1",
            "generated_by": "tools/gen_vectors.py",
        },
        "keccak256": [],
        "secp256k1": [],
        "authorization": [],
        "markers": [],
        "eip7851": [],
        "eip8151": [],
        "eip8476": [],
        "erc8010": [],
    }

    for payload in (b"", b"abc", b"The quick brown fox jumps over the lazy dog"):
        doc["keccak256"].append({"input": hx(payload), "digest": hx(keccak256(payload))})

    for key, nonce in ((KEY_A, 0xC0FFEE), (KEY_B, 0xDEADBEEF)):
        r, s, parity = secp256k1.sign(DIGEST, key, nonce)
        doc["secp256k1"].append(
            {
                "private_key": hex(key),
                "digest": hx(DIGEST),
                "nonce": hex(nonce),
                "r": hex(r),
                "s": hex(s),
                "y_parity": parity,
                "signer": hx(secp256k1.address(key)),
                "recovered": hx(secp256k1.recover_address(DIGEST, parity, r, s)),
            }
        )

    for chain_id, delegated_to in ((1, DELEGATE_A), (0, DELEGATE_B)):
        unsigned = Authorization(chain_id=chain_id, address=delegated_to, nonce=0)
        signed = unsigned.sign(KEY_A, nonce=0xFEEDFACE)
        doc["authorization"].append(
            {
                "chain_id": chain_id,
                "delegate": hx(delegated_to),
                "nonce": 0,
                "signing_hash": hx(unsigned.signing_hash()),
                "y_parity": signed.y_parity,
                "r": hex(signed.r),
                "s": hex(signed.s),
                "authority": hx(signed.authority()),
            }
        )

    code_samples = {
        "empty": b"",
        "delegation": DELEGATION_PREFIX + DELEGATE_A,
        "ecdsa_disabled": ECDSA_DISABLED_PREFIX + DELEGATE_A,
        "opt_out": OPT_OUT_MARKER,
        "contract": b"\x60\x00\x60\x00\xf3",
        "delegation_with_trailing_byte": DELEGATION_PREFIX + DELEGATE_A + b"\x00",
    }
    for name, code in code_samples.items():
        doc["markers"].append(
            {
                "name": name,
                "code": hx(code),
                "kind": markers.classify(code).value,
                "delegate": hx(markers.delegate_of(code)),
                "evm_visible_code": hx(markers.evm_visible_code(code)),
                "eip8151_permitted": markers.is_eip7702_delegated(code),
            }
        )

    transitions = (
        ("empty", "", "zero_delegate"),
        ("delegation", DELEGATE_B.hex(), "update"),
        ("ecdsa_disabled", DELEGATE_B.hex(), "redelegate"),
    )
    base = {
        "empty": b"",
        "delegation": DELEGATION_PREFIX + DELEGATE_A,
        "ecdsa_disabled": ECDSA_DISABLED_PREFIX + DELEGATE_A,
    }
    for name, delegate_hex, label in transitions:
        delegate = bytes(20) if not delegate_hex else bytes.fromhex(delegate_hex)
        result = eip7851.apply_self_delegate(base[name], delegate)
        doc["eip7851"].append(
            {
                "label": label,
                "input_code": hx(base[name]),
                "delegate": hx(delegate),
                "success": result.success,
                "new_code": hx(result.new_code),
                "gas_used": result.gas_used,
                "reason": result.reason,
            }
        )

    r, s, parity = secp256k1.sign(DIGEST, KEY_A, 0xC0FFEE)
    signer = secp256k1.address(KEY_A)
    v = 27 + parity
    for name, code in (
        ("plain_eoa", b""),
        ("delegated", DELEGATION_PREFIX + DELEGATE_A),
        ("ecdsa_disabled", ECDSA_DISABLED_PREFIX + DELEGATE_A),
        ("opt_out", OPT_OUT_MARKER),
        ("contract", b"\x60\x00\x60\x00\xf3"),
    ):
        db = eip8151.AccountDB(raw_code={signer: code})
        cold = eip8151.ecrecover_precompile(db, DIGEST, v, r, s)
        warm = eip8151.ecrecover_precompile(db, DIGEST, v, r, s)
        doc["eip8151"].append(
            {
                "signer": hx(signer),
                "digest": hx(DIGEST),
                "account_code": hx(code),
                "v": v,
                "r": hex(r),
                "s": hex(s),
                "output": hx(cold.output),
                "permitted": cold.permitted,
                "gas_cold": cold.gas_used,
                "gas_warm": warm.gas_used,
            }
        )

    sender = bytes.fromhex("28" * 20)
    current_chain = 1

    def tx_json(tx: SetCodeTransaction) -> dict:
        return {
            "sender": hx(tx.sender),
            "destination": hx(tx.destination),
            "value": tx.value,
            "data": hx(tx.data),
            "authorization_list_length": len(tx.authorization_list),
            "access_list_length": len(tx.access_list),
            "chain_id": tx.chain_id,
            "gas_limit": tx.gas_limit,
            "nonce": tx.nonce,
        }

    def good_tx(**overrides) -> SetCodeTransaction:
        fields = dict(sender=sender, destination=sender, chain_id=current_chain)
        fields.update(overrides)
        return SetCodeTransaction(**fields)

    opt_cases = [
        ("apply_to_plain_eoa", b"", good_tx()),
        ("apply_over_existing_delegation", DELEGATION_PREFIX + DELEGATE_A,
         good_tx()),
        ("apply_over_ecdsa_disabled", ECDSA_DISABLED_PREFIX + DELEGATE_A,
         good_tx()),
        ("repeat_consumes_gas", OPT_OUT_MARKER, good_tx(gas_limit=40000)),
        ("gas_limit_too_low", b"", good_tx(gas_limit=eip8476.OPT_OUT_GAS - 1)),
        ("chain_id_mismatch", b"", good_tx(chain_id=5)),
        ("nonce_out_of_range", b"", good_tx(nonce=2**64)),
        ("non_empty_authorization_list", b"", good_tx(authorization_list=(b"",))),
        ("destination_not_sender", b"", good_tx(destination=DELEGATE_A)),
        ("nonzero_value", b"", good_tx(value=1)),
        ("non_empty_data", b"", good_tx(data=b"\x01")),
        ("non_empty_access_list", b"", good_tx(access_list=((1,),))),
    ]
    for name, code, tx in opt_cases:
        outcome = eip8476.apply_opt_out(code, tx, current_chain_id=current_chain)
        doc["eip8476"].append(
            {
                "case": name,
                "input_code": hx(code),
                "tx": tx_json(tx),
                "current_chain_id": current_chain,
                "status": outcome.status.value,
                "reason": outcome.reason.value if outcome.reason else None,
                "new_code": hx(outcome.new_code),
                "gas_used": outcome.gas_used,
                "already_marked": outcome.already_marked,
            }
        )

    auth_blob = b"".join(
        [
            (1).to_bytes(32, "big"),
            DELEGATE_A.rjust(32, b"\x00"),
            (0).to_bytes(32, "big"),
            (0).to_bytes(32, "big"),
            (1).to_bytes(32, "big"),
            (2).to_bytes(32, "big"),
        ]
    )
    wrapped = erc8010.wrap_signature(
        b"\x01\x02", auth_blob, DELEGATE_B, b"\x03", layout=erc8010.LAYOUT_SIGNER
    )
    parsed = erc8010.parse_wrapped(wrapped, layout=erc8010.LAYOUT_SIGNER)
    doc["erc8010"].append(
        {
            "layout": "signer",
            "wrapped": hx(wrapped),
            "signature": hx(parsed.signature),
            "init_to": hx(parsed.init_to),
            "init_data": hx(parsed.init_data),
            "delegated": hx(parsed.delegated),
            "layouts_conflict": erc8010.layouts_conflict(),
        }
    )

    return doc


def main() -> None:
    doc = build()
    target = ROOT / "vectors" / "conformance.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    total = sum(len(v) for k, v in doc.items() if k != "meta")
    print(f"wrote {target.relative_to(ROOT)} ({total} vectors)")


if __name__ == "__main__":
    main()
