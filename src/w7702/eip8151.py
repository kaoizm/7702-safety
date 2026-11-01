"""EIP-8151: Account Code Restricted ecRecover.

Models the modified ``ecRecover`` precompile at ``0x00...01``:

  1. charge 3000 gas
  2. recover; on failure return empty output, stop
  3. charge (COLD_ACCOUNT_ACCESS | WARM_ACCESS) + one WARM_ACCESS for the read
  4. warm the recovered address, record the read, load *raw* code
  5. return the 32-byte address only if raw code is empty or exactly
     ``0xef0100 || delegate``; otherwise return empty output

Both success and rejection return ``success = 1`` with empty vs 32-byte output.
The precompile only reads; it never follows the delegation indicator.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import secp256k1
from .markers import is_eip7702_delegated

BASE_GAS = 3000
COLD_ACCOUNT_ACCESS = 3000
WARM_ACCESS = 100


class OutOfGas(RuntimeError):
    pass


@dataclass
class AccountDB:
    """Minimal state view: raw code per address plus the warm-address set."""

    raw_code: dict[bytes, bytes] = field(default_factory=dict)
    accessed_addresses: set[bytes] = field(default_factory=set)

    def get_raw_code(self, address: bytes) -> bytes:
        return self.raw_code.get(address, b"")

    def is_warm(self, address: bytes) -> bool:
        return address in self.accessed_addresses


@dataclass(frozen=True)
class ECRecoverResult:
    output: bytes
    gas_used: int
    recovered: bytes | None
    permitted: bool


def code_check_cost(db: AccountDB, recovered: bytes) -> int:
    cold_or_warm = WARM_ACCESS if db.is_warm(recovered) else COLD_ACCOUNT_ACCESS
    return cold_or_warm + WARM_ACCESS


def ecrecover_precompile(
    db: AccountDB,
    digest: bytes,
    v: int,
    r: int,
    s: int,
    *,
    gas_limit: int | None = None,
) -> ECRecoverResult:
    gas_used = BASE_GAS
    if gas_limit is not None and gas_used > gas_limit:
        raise OutOfGas("base gas")

    # The precompile takes the classic 27/28 encoding; the library uses 0/1.
    if v in (27, 28):
        y_parity = v - 27
    elif v in (0, 1):
        y_parity = v
    else:
        return ECRecoverResult(b"", gas_used, None, False)

    payload = secp256k1.recover(digest, y_parity, r, s)
    if payload is None:
        return ECRecoverResult(b"", gas_used, None, False)

    recovered = secp256k1.address_from_point(payload)
    gas_used += code_check_cost(db, recovered)
    if gas_limit is not None and gas_used > gas_limit:
        raise OutOfGas("code check gas")

    db.accessed_addresses.add(recovered)
    raw_code = db.get_raw_code(recovered)
    permitted = is_eip7702_delegated(raw_code)

    if permitted:
        return ECRecoverResult(
            recovered.rjust(32, b"\x00"), gas_used, recovered, True
        )
    return ECRecoverResult(b"", gas_used, recovered, False)
