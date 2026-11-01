"""Pure-Python Keccak-256 with Ethereum's original padding (0x01), not SHA3 (0x06).

Reference: Keccak-f[1600] specification, 24 rounds, rate 1088 bits (136 bytes),
capacity 512 bits.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# Rho offsets, indexed [x][y].
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_RATE_BYTES = 136


def _rol(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _keccak_f1600(a: list[int]) -> None:
    for rnd in range(24):
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]

        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])

        # chi
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])

        # iota
        a[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of ``data`` (32 bytes)."""
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % _RATE_BYTES != 0:
        msg.append(0x00)
    msg[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(msg), _RATE_BYTES):
        block = msg[offset:offset + _RATE_BYTES]
        for i in range(_RATE_BYTES // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f1600(state)

    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out[:32]
