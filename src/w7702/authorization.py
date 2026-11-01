"""EIP-7702 authorization tuples.

An authorization is the tuple ``(chain_id, address, nonce, y_parity, r, s)``.
The signer signs ``keccak256(0x05 || rlp([chain_id, address, nonce]))`` where
``0x05`` is the EIP-7702 magic byte.

Reference: EIP-7702 "Set code transaction" / "Authorization list".
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import rlp, secp256k1
from .crypto.keccak import keccak256

MAGIC = 0x05


@dataclass(frozen=True)
class Authorization:
    chain_id: int
    address: bytes
    nonce: int
    y_parity: int = 0
    r: int = 0
    s: int = 0

    def __post_init__(self) -> None:
        if len(self.address) != 20:
            raise ValueError("authorization address must be 20 bytes")
        if self.chain_id < 0 or self.nonce < 0:
            raise ValueError("chain_id and nonce must be non-negative")

    def signing_hash(self) -> bytes:
        return keccak256(
            bytes([MAGIC])
            + rlp.encode([self.chain_id, self.address, self.nonce])
        )

    def sign(self, private_key: int, nonce: int) -> "Authorization":
        r, s, y_parity = secp256k1.sign(self.signing_hash(), private_key, nonce)
        return Authorization(
            chain_id=self.chain_id,
            address=self.address,
            nonce=self.nonce,
            y_parity=y_parity,
            r=r,
            s=s,
        )

    @property
    def is_signed(self) -> bool:
        return self.r != 0 and self.s != 0

    def authority(self) -> bytes | None:
        """Recover the EOA that signed this authorization."""
        if not self.is_signed:
            return None
        return secp256k1.recover_address(
            self.signing_hash(), self.y_parity, self.r, self.s
        )


def is_valid_authority(authority: bytes) -> bool:
    """EIP-7702: an authorization is skipped if authority is zero or the
    delegate address (self-delegation to itself is a no-op)."""
    return len(authority) == 20 and any(authority)
