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

    def sign(self, private_key: int, k: int) -> "Authorization":
        """Sign with an explicit ECDSA nonce ``k`` (never reuse it)."""
        r, s, y_parity = secp256k1.sign(self.signing_hash(), private_key, k)
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
    """An authorization is skipped when recovery yields the zero address.

    (The delegate-zero rule is a different step: it clears the account's code.)
    """
    return len(authority) == 20 and any(authority)


# EIP-7702 step 2: "Verify the nonce is less than 2**64 - 1." Step 9 increments
# the nonce, so 2**64 - 1 must be rejected.
MAX_NONCE = 2**64 - 2
MAX_CHAIN_ID = 2**256 - 1


def validate(authorization: Authorization, *, current_chain_id: int | None = None) -> list[str]:
    """Return the EIP-7702 validity checks this tuple fails (empty = valid).

    Checks, in spec order:
      * ``chain_id`` is 0 or the current chain id
      * ``nonce < 2**64 - 1`` (step 2; step 9 increments it)
      * ``s <= secp256k1n / 2`` (EIP-2, referenced by EIP-7702 step 3)
      * ``r`` and ``s`` are in ``(0, n)`` and ``y_parity`` is 0/1
      * recovery yields a non-zero authority (step 3 skips failures)

    Recovering the authority is not a *signature* check: ``ecrecover`` itself
    accepts high-s (homestead=false). The tuple rules are stricter than the
    precompile, which is why both exist here.
    """
    errors: list[str] = []

    if not 0 <= authorization.chain_id <= MAX_CHAIN_ID:
        errors.append("chain_id out of range")
    elif current_chain_id is not None and authorization.chain_id not in (0, current_chain_id):
        errors.append("chain_id mismatch")

    if not 0 <= authorization.nonce <= MAX_NONCE:
        errors.append("nonce out of range")

    if authorization.y_parity not in (0, 1):
        errors.append("y_parity must be 0 or 1")

    if not 0 < authorization.r < secp256k1.N:
        errors.append("r out of range")
    if not 0 < authorization.s < secp256k1.N:
        errors.append("s out of range")
    elif authorization.s > secp256k1.N // 2:
        errors.append("high-s signature (EIP-2)")

    authority = authorization.authority()
    if authority is None:
        errors.append("authority unrecoverable")
    elif not is_valid_authority(authority):
        errors.append("authority is the zero address")

    return errors
