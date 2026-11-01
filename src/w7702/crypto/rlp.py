"""Minimal RLP encoder, sufficient for EIP-7702 authorization tuples.

``encode`` dispatches on Python type so call sites cannot accidentally pass an
already-encoded payload back through the encoder:

    encode(1)            -> 0x01
    encode(b"dog")       -> 0x83 "dog"
    encode([1, b"\\xaa"*20, 0])  -> list of encoded items
"""

from __future__ import annotations


def _length_prefix(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(encoded)]) + encoded


def encode_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    return _length_prefix(len(value), 0x80) + value


def encode_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("RLP cannot encode negative integers")
    if value == 0:
        return encode_bytes(b"")
    length = (value.bit_length() + 7) // 8
    return encode_bytes(value.to_bytes(length, "big"))


def encode(value) -> bytes:
    if isinstance(value, bool):
        raise TypeError("RLP does not encode booleans; use 0/1 explicitly")
    if isinstance(value, int):
        return encode_int(value)
    if isinstance(value, (bytes, bytearray)):
        return encode_bytes(bytes(value))
    if isinstance(value, (list, tuple)):
        payload = b"".join(encode(item) for item in value)
        return _length_prefix(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode {type(value)!r}")


def encode_list(items) -> bytes:
    """Encode a list; each item is encoded recursively (convenience alias)."""
    return encode(list(items))
