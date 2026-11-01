"""ERC-8010: Pre-delegated Signature Verification.

Wire format (spec, "Signer Side"):

    wrapped = signature || context || uint256(context.length) || MAGIC
    context = abi.encode(authorization, init_to, init_data)
    MAGIC   = 0x8010 repeated 16 times (32 bytes)

NOTE: the "Verifier Side" section decodes the context as
``(authorization, init_data, init_to)`` with types ``(bytes, bytes, address)``,
which contradicts the signer-side encoding order and types. Both layouts are
implemented; ``layouts_conflict()`` documents the discrepancy and the test
suite pins it. This is filed as finding F-1 in ``docs/02-findings.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

MAGIC = bytes.fromhex("8010" * 16)

LAYOUT_SIGNER = ("bytes", "address", "bytes")   # authorization, init_to, init_data
LAYOUT_VERIFIER = ("bytes", "bytes", "address")  # authorization, init_data, init_to


class DecodeError(ValueError):
    pass


# ---------------------------------------------------------------- ABI helpers


def _pad32(data: bytes) -> bytes:
    remainder = len(data) % 32
    return data + b"\x00" * (32 - remainder if remainder else 0)


def abi_encode(types: tuple[str, ...], values: tuple) -> bytes:
    if len(types) != len(values):
        raise ValueError("types/values length mismatch")
    head_size = 32 * len(types)
    head: list[bytes] = []
    tail: list[bytes] = []
    offset = head_size
    for typ, value in zip(types, values):
        if typ == "address":
            if len(value) != 20:
                raise ValueError("address must be 20 bytes")
            head.append(value.rjust(32, b"\x00"))
        elif typ == "bytes":
            encoded = len(value).to_bytes(32, "big") + _pad32(value)
            head.append(offset.to_bytes(32, "big"))
            tail.append(encoded)
            offset += len(encoded)
        else:
            raise ValueError(f"unsupported ABI type {typ}")
    return b"".join(head) + b"".join(tail)


def abi_decode(types: tuple[str, ...], data: bytes) -> tuple:
    if len(data) < 32 * len(types):
        raise DecodeError("context too short")
    values: list = []
    for index, typ in enumerate(types):
        word = data[index * 32:(index + 1) * 32]
        if typ == "address":
            values.append(word[12:32])
        elif typ == "bytes":
            offset = int.from_bytes(word, "big")
            if offset + 32 > len(data):
                raise DecodeError("dynamic offset out of bounds")
            length = int.from_bytes(data[offset:offset + 32], "big")
            start = offset + 32
            end = start + length
            if end > len(data):
                raise DecodeError("dynamic payload out of bounds")
            values.append(data[start:end])
        else:
            raise ValueError(f"unsupported ABI type {typ}")
    return tuple(values)


# ------------------------------------------------------------- wire format


def wrap_signature(
    signature: bytes,
    authorization: bytes,
    init_to: bytes,
    init_data: bytes,
    *,
    layout: tuple[str, ...] = LAYOUT_SIGNER,
) -> bytes:
    if layout == LAYOUT_SIGNER:
        context = abi_encode(LAYOUT_SIGNER, (authorization, init_to, init_data))
    elif layout == LAYOUT_VERIFIER:
        # deliberately encoded so that the verifier-order decode round-trips
        context = abi_encode(LAYOUT_VERIFIER, (authorization, init_data, init_to))
    else:
        raise ValueError("unknown layout")
    return signature + context + len(context).to_bytes(32, "big") + MAGIC


@dataclass(frozen=True)
class ParsedSignature:
    signature: bytes
    context: bytes
    authorization: bytes
    init_to: bytes
    init_data: bytes
    delegated: bytes  # 20-byte delegate address encoded in the authorization


def _decode_authorization(blob: bytes) -> bytes:
    """authorization = abi.encode(chain_id, address, nonce, y_parity, r, s)."""
    if len(blob) != 32 * 6:
        raise DecodeError("authorization must be 6 ABI words")
    return blob[32 + 12:64]


def parse_wrapped(
    wrapped: bytes, *, layout: tuple[str, ...] = LAYOUT_SIGNER
) -> ParsedSignature:
    if len(wrapped) < 96 or not wrapped.endswith(MAGIC):
        raise DecodeError("not an ERC-8010 wrapped signature")

    context_length = int.from_bytes(wrapped[-64:-32], "big")
    if context_length > len(wrapped) - 64:
        raise DecodeError("context length exceeds payload")
    context_start = len(wrapped) - 64 - context_length
    signature = wrapped[:context_start]
    context = wrapped[context_start:len(wrapped) - 64]

    if layout == LAYOUT_SIGNER:
        authorization, init_to, init_data = abi_decode(LAYOUT_SIGNER, context)
    elif layout == LAYOUT_VERIFIER:
        authorization, init_data, init_to = abi_decode(LAYOUT_VERIFIER, context)
    else:
        raise ValueError("unknown layout")

    return ParsedSignature(
        signature=signature,
        context=context,
        authorization=authorization,
        init_to=init_to,
        init_data=init_data,
        delegated=_decode_authorization(authorization),
    )


def layouts_conflict() -> bool:
    """True: the two layouts in the spec disagree on both order and types."""
    return LAYOUT_SIGNER != LAYOUT_VERIFIER


# ------------------------------------------------- verification procedure


class VerifierEnv:
    """Callback surface the procedure runs against (a real verifier would RPC)."""

    def code(self, account: bytes) -> bytes:  # pragma: no cover - protocol
        raise NotImplementedError

    def is_valid_signature(
        self, account: bytes, digest: bytes, signature: bytes
    ) -> bool:  # pragma: no cover - protocol
        raise NotImplementedError

    def call(
        self, target: bytes, data: bytes, authorization: bytes
    ) -> bool:  # pragma: no cover - protocol
        raise NotImplementedError

    def erc6492_verify(self, account: bytes, digest: bytes, signature: bytes) -> bool:
        return False

    def ecrecover_verify(self, account: bytes, digest: bytes, signature: bytes) -> bool:
        return False


def verify(
    wrapped: bytes,
    account: bytes,
    digest: bytes,
    env: VerifierEnv,
    *,
    layout: tuple[str, ...] = LAYOUT_SIGNER,
    allow_plain: bool = True,
) -> bool:
    """Model of the ERC-8010 verification procedure.

    Returns True when the signature is valid for ``account`` over ``digest``.
    ``allow_plain`` permits falling back to ERC-6492 when the signature is not
    wrapped (step 2 of the procedure).
    """
    if not wrapped.endswith(MAGIC):
        if not allow_plain:
            raise DecodeError("not wrapped")
        return env.erc6492_verify(account, digest, wrapped)

    parsed = parse_wrapped(wrapped, layout=layout)
    raw_code = env.code(account)
    delegation_indicator = b"\xef\x01\x00" + parsed.delegated

    if raw_code == delegation_indicator:
        if env.is_valid_signature(account, digest, parsed.signature):
            return True
        return env.ecrecover_verify(account, digest, parsed.signature)

    ok = env.call(parsed.init_to, parsed.init_data, parsed.authorization)
    if not ok:
        return False
    return env.is_valid_signature(account, digest, parsed.signature)
