"""EIP-8476: Permanent EOA Delegation Opt-Out.

Model of the opt-out form (type-4 set-code transaction, empty authorization
list, destination == sender, value 0, empty data and access list) and the
resulting account semantics.

Normative points modelled here (draft head f1a4071, 2026-11-01):

  * opt-out sets the sender's raw code to the 3-byte marker ``0xef0200``
  * intrinsic gas and gas used MUST both equal ``OPT_OUT_GAS`` (33500); a gas
    limit below that MUST make the transaction invalid
  * the outer transaction chain ID MUST equal the current chain ID; the
    ``chain_id = 0`` exception for EIP-7702 authorization tuples does not apply
  * the sender nonce MUST satisfy ``nonce < 2**64`` (EIP-2681)
  * an existing EIP-7702 delegation is replaced directly
  * repeating the operation on an already marked account is valid, leaves code
    unchanged, and consumes the ordinary nonce and ``OPT_OUT_GAS``
    (Test Cases row: code M, gas limit 40000 -> gas used 33500, unused 6500)
  * EIP-7702 authorizations for a marked authority are skipped
  * EVM execution/inspection sees empty code; ``eth_getCode``/``eth_getProof``
    expose the raw marker
  * transaction pools treat the account as an empty-code EOA for pending-tx
    limits
  * the guarantee is per chain
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .markers import OPT_OUT_MARKER, CodeKind, classify, evm_visible_code

OPT_OUT_GAS = 33500
# EIP-2681 / EIP-8476: "nonce < 2**64 - 1" (the nonce is incremented after
# inclusion, so 2**64 - 1 cannot be a valid sender nonce).
MAX_NONCE = 2**64 - 2


class OptOutStatus(str, Enum):
    APPLIED = "applied"
    REJECTED = "rejected"


class RejectReason(str, Enum):
    NON_EMPTY_AUTHORIZATION_LIST = "non_empty_authorization_list"
    DESTINATION_NOT_SENDER = "destination_not_sender"
    NONZERO_VALUE = "nonzero_value"
    NON_EMPTY_DATA = "non_empty_data"
    NON_EMPTY_ACCESS_LIST = "non_empty_access_list"
    CHAIN_ID_MISMATCH = "chain_id_mismatch"
    GAS_LIMIT_TOO_LOW = "gas_limit_too_low"
    NONCE_OUT_OF_RANGE = "nonce_out_of_range"
    ACCOUNT_HAS_CODE = "account_has_code"
    ECDSA_DISABLED_SENDER = "ecdsa_disabled_sender"


@dataclass(frozen=True)
class SetCodeTransaction:
    sender: bytes
    destination: bytes
    value: int = 0
    data: bytes = b""
    access_list: tuple = ()
    authorization_list: tuple = ()
    chain_id: int = 0
    gas_limit: int = OPT_OUT_GAS
    nonce: int = 0


@dataclass(frozen=True)
class OptOutResult:
    status: OptOutStatus
    gas_used: int
    new_code: bytes
    reason: RejectReason | None = None
    already_marked: bool = False


def validate_form(tx: SetCodeTransaction) -> RejectReason | None:
    if len(tx.authorization_list) != 0:
        return RejectReason.NON_EMPTY_AUTHORIZATION_LIST
    if tx.destination != tx.sender:
        return RejectReason.DESTINATION_NOT_SENDER
    if tx.value != 0:
        return RejectReason.NONZERO_VALUE
    if len(tx.data) != 0:
        return RejectReason.NON_EMPTY_DATA
    if len(tx.access_list) != 0:
        return RejectReason.NON_EMPTY_ACCESS_LIST
    return None


def validate_transaction(
    tx: SetCodeTransaction, current_chain_id: int | None = None
) -> RejectReason | None:
    """Form plus the transaction-validity rules the draft states."""
    reason = validate_form(tx)
    if reason is not None:
        return reason
    if current_chain_id is not None and tx.chain_id != current_chain_id:
        return RejectReason.CHAIN_ID_MISMATCH
    if tx.gas_limit < OPT_OUT_GAS:
        return RejectReason.GAS_LIMIT_TOO_LOW
    if not 0 <= tx.nonce <= MAX_NONCE:
        return RejectReason.NONCE_OUT_OF_RANGE
    return None


def apply_opt_out(
    raw_code: bytes,
    tx: SetCodeTransaction,
    *,
    current_chain_id: int | None = None,
) -> OptOutResult:
    reason = validate_transaction(tx, current_chain_id)
    if reason is not None:
        return OptOutResult(OptOutStatus.REJECTED, 0, raw_code, reason)

    kind = classify(raw_code)
    if kind is CodeKind.OPT_OUT:
        # Repeat: valid, code unchanged, ordinary nonce and OPT_OUT_GAS.
        return OptOutResult(
            OptOutStatus.APPLIED, OPT_OUT_GAS, raw_code, already_marked=True
        )
    if kind in (CodeKind.EMPTY, CodeKind.DELEGATION):
        return OptOutResult(OptOutStatus.APPLIED, OPT_OUT_GAS, OPT_OUT_MARKER)
    if kind is CodeKind.ECDSA_DISABLED:
        # Unreachable in practice: EIP-7851 makes ECDSA transactions from a
        # 0xef0101 sender invalid, so such an account cannot originate this
        # transaction. Rejected explicitly because 0xef0200 is ECDSA-enabled
        # state and would otherwise undo 0xef0101.
        return OptOutResult(
            OptOutStatus.REJECTED, 0, raw_code, RejectReason.ECDSA_DISABLED_SENDER
        )
    return OptOutResult(
        OptOutStatus.REJECTED, 0, raw_code, RejectReason.ACCOUNT_HAS_CODE
    )


def authorization_eligible(authority_raw_code: bytes) -> bool:
    """EIP-7702 authorizations for an opted-out authority are skipped.

    Scoped to the opt-out rule only; full EIP-7702 eligibility also requires
    empty code or a delegation indicator.
    """
    return classify(authority_raw_code) is not CodeKind.OPT_OUT


def execution_code(raw_code: bytes) -> bytes:
    """CALL/EXTCODE* view: opted-out accounts execute as empty code."""
    return evm_visible_code(raw_code)


def raw_code_for_rpc(raw_code: bytes) -> bytes:
    """eth_getCode / eth_getProof expose the raw marker."""
    return raw_code


def txpool_pending_limit_applies(raw_code: bytes) -> bool:
    """A permanently opted-out account is not a delegate: it SHOULD be treated
    like an empty-code EOA for pending-transaction limits (geth legacypool
    ``checkDelegationLimit``)."""
    return classify(raw_code) is not CodeKind.OPT_OUT
