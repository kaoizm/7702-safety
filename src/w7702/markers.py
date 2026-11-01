"""Account-code classification for EIP-7702 and its security extensions.

The account code of an EOA is either empty or a 23-byte delegation indicator:

    EIP-7702  delegated       0xef0100 || delegate
    EIP-7851  ECDSA disabled  0xef0101 || delegate
    EIP-8476  permanent opt-out 0xef0200          (3 bytes, no payload)

``classify`` works on *raw* state code. ``evm_visible_code`` applies the
EIP-8476 refinement: an opted-out account keeps the marker in state but the EVM
sees empty code, so it behaves like a normal EOA.
"""

from __future__ import annotations

from enum import Enum

DELEGATION_PREFIX = b"\xef\x01\x00"
ECDSA_DISABLED_PREFIX = b"\xef\x01\x01"
OPT_OUT_MARKER = b"\xef\x02\x00"

DELEGATION_LENGTH = 23


class CodeKind(str, Enum):
    EMPTY = "empty"
    DELEGATION = "delegation"                 # 0xef0100 || delegate
    ECDSA_DISABLED = "ecdsa_disabled"         # 0xef0101 || delegate
    OPT_OUT = "opt_out"                       # 0xef0200
    OTHER = "other"


def classify(code: bytes) -> CodeKind:
    if len(code) == 0:
        return CodeKind.EMPTY
    if len(code) == DELEGATION_LENGTH and code[:3] == DELEGATION_PREFIX:
        return CodeKind.DELEGATION
    if len(code) == DELEGATION_LENGTH and code[:3] == ECDSA_DISABLED_PREFIX:
        return CodeKind.ECDSA_DISABLED
    if code == OPT_OUT_MARKER:
        return CodeKind.OPT_OUT
    return CodeKind.OTHER


def delegate_of(code: bytes) -> bytes | None:
    """Return the delegation target for a delegated account, else None."""
    if classify(code) in (CodeKind.DELEGATION, CodeKind.ECDSA_DISABLED):
        return code[3:23]
    return None


def delegation_indicator(delegate: bytes) -> bytes:
    if len(delegate) != 20:
        raise ValueError("delegate must be 20 bytes")
    return DELEGATION_PREFIX + delegate


def ecdsa_disabled_indicator(delegate: bytes) -> bytes:
    if len(delegate) != 20:
        raise ValueError("delegate must be 20 bytes")
    return ECDSA_DISABLED_PREFIX + delegate


def evm_visible_code(raw_code: bytes) -> bytes:
    """Code the EVM executes and inspects (EIP-8476 refinement, 2026-10-31).

    An opted-out account is treated as empty code by CALL/EXTCODESIZE/etc.,
    while ``eth_getCode``/``eth_getProof`` still expose the raw marker.
    """
    if classify(raw_code) is CodeKind.OPT_OUT:
        return b""
    return raw_code


def is_eip7702_delegated(code: bytes) -> bool:
    """EIP-8151's eligibility predicate, verbatim from the spec:

        is_permitted = len(code) == 0 or (len(code) == 23 and code[:3] == 0xef0100)
    """
    return len(code) == 0 or (
        len(code) == DELEGATION_LENGTH and code[:3] == DELEGATION_PREFIX
    )


def is_permitted_ecrecover(
    code: bytes, *, allow_eip8476_opt_out_marker: bool = False
) -> bool:
    """EIP-8151 predicate, optionally with the proposed EIP-8476 marker clause.

    ``allow_eip8476_opt_out_marker=False`` (the default) is EIP-8151 as drafted:
    only empty code and ``0xef0100 || delegate`` are eligible, so the exact
    three-byte opt-out marker ``0xef0200`` is rejected.

    ``True`` is the change proposed in ethereum/EIPs#12605: an opted-out account
    keeps ordinary EOA authorization, so exactly ``0xef0200`` becomes eligible.
    The flag is named after the marker because that is the only account state it
    changes.
    """
    if is_eip7702_delegated(code):
        return True
    return allow_eip8476_opt_out_marker and classify(code) is CodeKind.OPT_OUT
