"""EIP-8476: Permanent EOA Delegation Opt-Out.

Model of the opt-out form (type-4 set-code transaction, empty authorization
list, destination == sender, value 0, empty data and access list) and the
resulting account semantics:

  * sender's raw code becomes the 3-byte marker ``0xef0200``
  * fixed 33500 gas, no EVM code executes
  * the marker can never be replaced or cleared by a later authorization
  * EIP-7702 authorizations for a marked authority are skipped
  * EVM execution/inspection sees empty code; ``eth_getCode``/``eth_getProof``
    expose the raw marker
  * transaction pools treat the account as an empty-code EOA for pending-tx limits
  * the guarantee is per chain: a chain_id = 0 authorization is still valid on
    every other 7702 chain where the account has not opted out

Open questions are recorded in ``docs/02-findings.md`` rather than silently
guessed; each is surfaced as a distinct rejection reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .markers import OPT_OUT_MARKER, CodeKind, classify, evm_visible_code

OPT_OUT_GAS = 33500


class OptOutStatus(str, Enum):
    APPLIED = "applied"
    ALREADY_OPTED_OUT = "already_opted_out"
    REJECTED = "rejected"


class RejectReason(str, Enum):
    NON_EMPTY_AUTHORIZATION_LIST = "non_empty_authorization_list"
    DESTINATION_NOT_SENDER = "destination_not_sender"
    NONZERO_VALUE = "nonzero_value"
    NON_EMPTY_DATA = "non_empty_data"
    NON_EMPTY_ACCESS_LIST = "non_empty_access_list"
    ACCOUNT_HAS_CODE = "account_has_code"


@dataclass(frozen=True)
class SetCodeTransaction:
    sender: bytes
    destination: bytes
    value: int = 0
    data: bytes = b""
    access_list: tuple = ()
    authorization_list: tuple = ()


@dataclass(frozen=True)
class OptOutResult:
    status: OptOutStatus
    gas_used: int
    new_code: bytes
    reason: RejectReason | None = None


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


def apply_opt_out(raw_code: bytes, tx: SetCodeTransaction) -> OptOutResult:
    reason = validate_form(tx)
    if reason is not None:
        return OptOutResult(OptOutStatus.REJECTED, 0, raw_code, reason)

    kind = classify(raw_code)
    if kind is CodeKind.OPT_OUT:
        return OptOutResult(OptOutStatus.ALREADY_OPTED_OUT, 0, raw_code)
    if kind is not CodeKind.EMPTY:
        # The spec does not state how opt-out interacts with an existing
        # 0xef0100/0xef0101 delegation; we refuse rather than guess.
        return OptOutResult(
            OptOutStatus.REJECTED, 0, raw_code, RejectReason.ACCOUNT_HAS_CODE
        )

    return OptOutResult(OptOutStatus.APPLIED, OPT_OUT_GAS, OPT_OUT_MARKER)


def authorization_eligible(authority_raw_code: bytes) -> bool:
    """EIP-7702 authorizations for an opted-out authority are skipped."""
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
