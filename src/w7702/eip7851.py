"""EIP-7851: Code-Controlled EOA Delegation.

Models the state transition performed by the ``SETSELFDELEGATE`` opcode and the
two validation rules the EIP adds:

  * an EIP-7702 authorization signed by an authority whose raw code is
    ``0xef0101 || delegate`` MUST be skipped;
  * an ECDSA-authenticated transaction whose recovered sender has that code is
    invalid and MUST NOT be included.

Irreversible invariant: once ECDSA authority is disabled it can never be
restored. Only the delegate target may change, and only through wallet code.
"""

from __future__ import annotations

from dataclasses import dataclass

from .markers import (
    DELEGATION_LENGTH,
    DELEGATION_PREFIX,
    ECDSA_DISABLED_PREFIX,
    CodeKind,
    classify,
)

SETSELFDELEGATE_GAS = 9500
ZERO_ADDRESS = bytes(20)


class StaticContextError(RuntimeError):
    """SETSELFDELEGATE executed in a static context: exceptional halt."""


@dataclass(frozen=True)
class SelfDelegateResult:
    success: bool
    gas_used: int
    new_code: bytes
    reason: str


def apply_self_delegate(
    raw_code: bytes, delegate_address: bytes, *, is_static: bool = False
) -> SelfDelegateResult:
    """Execute ``SETSELFDELEGATE(delegate_address)`` against an account.

    Spec order of checks:
      1. static context -> exceptional halt
      2. delegate == address(0) -> push 0, no state change
      3. raw code is 23 bytes and starts with 0xef0100 or 0xef0101 -> write
         0xef0101 || delegate, push 1
      4. otherwise -> push 0, no state change
    """
    if is_static:
        raise StaticContextError("SETSELFDELEGATE in static context")
    if len(delegate_address) != 20:
        raise ValueError("delegate address must be 20 bytes")

    if delegate_address == ZERO_ADDRESS:
        return SelfDelegateResult(False, SETSELFDELEGATE_GAS, raw_code, "zero_delegate")

    kind = classify(raw_code)
    if kind in (CodeKind.DELEGATION, CodeKind.ECDSA_DISABLED):
        return SelfDelegateResult(
            True,
            SETSELFDELEGATE_GAS,
            ECDSA_DISABLED_PREFIX + delegate_address,
            "delegation_updated",
        )

    return SelfDelegateResult(False, SETSELFDELEGATE_GAS, raw_code, "not_delegated")


def authorization_allowed(authority_raw_code: bytes) -> bool:
    """False when the authority has permanently burned ECDSA authority."""
    return classify(authority_raw_code) is not CodeKind.ECDSA_DISABLED


def transaction_allowed(sender_raw_code: bytes) -> bool:
    """False when the recovered sender is ECDSA-disabled."""
    return classify(sender_raw_code) is not CodeKind.ECDSA_DISABLED


def is_ecdsa_disabled(raw_code: bytes) -> bool:
    return (
        len(raw_code) == DELEGATION_LENGTH
        and raw_code[:3] == ECDSA_DISABLED_PREFIX
    )


def is_ecdsa_enabled_delegation(raw_code: bytes) -> bool:
    return (
        len(raw_code) == DELEGATION_LENGTH
        and raw_code[:3] == DELEGATION_PREFIX
    )
