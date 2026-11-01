"""Pure-Python secp256k1: deterministic signing and public-key recovery.

Only what the 7702 standards need:
  * sign   - produce (r, s, y_parity) for a 32-byte digest
  * recover - recover the signer public key from (digest, y_parity, r, s)
  * address - keccak256(uncompressed pubkey)[12:]

No SEC1 encoding, no DER, no BIP32. Kept intentionally small so it can be
audited alongside the test vectors it produces.
"""

from __future__ import annotations

from .keccak import keccak256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = tuple[int, int] | None
G: Point = (GX, GY)


def _inv(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) % P * _inv(2 * p[1], P) % P
    else:
        lam = (q[1] - p[1]) % P * _inv((q[0] - p[0]) % P, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)


def _mul(k: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _lift_x(x: int, y_parity: int) -> Point:
    if x >= P:
        return None
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    if (beta * beta - alpha) % P != 0:
        return None
    y = beta if (beta & 1) == y_parity else P - beta
    return (x, y)


def public_key(private_key: int) -> Point:
    if not 0 < private_key < N:
        raise ValueError("private key out of range")
    return _mul(private_key, G)


def address_from_point(point: Point) -> bytes:
    if point is None:
        raise ValueError("invalid point")
    raw = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return keccak256(raw)[12:]


def address(private_key: int) -> bytes:
    return address_from_point(public_key(private_key))


def recover(digest: bytes, y_parity: int, r: int, s: int) -> Point:
    """Recover the signer public key, or return None."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    if not (0 < r < N and 0 < s < N):
        return None
    if y_parity not in (0, 1):
        return None
    r_point = _lift_x(r, y_parity)
    if r_point is None:
        return None
    e = int.from_bytes(digest, "big")
    r_inv = _inv(r, N)
    # Q = r^-1 (s*R - e*G)
    minus_e_g = _mul((N - (e % N)) % N, G) if e % N else None
    return _mul(r_inv, _add(_mul(s, r_point), minus_e_g))


def recover_address(digest: bytes, y_parity: int, r: int, s: int) -> bytes | None:
    point = recover(digest, y_parity, r, s)
    return None if point is None else address_from_point(point)


def sign(digest: bytes, private_key: int, nonce: int) -> tuple[int, int, int]:
    """Sign ``digest`` with an explicit nonce ``k``.

    ``k`` is supplied by the caller so test vectors stay reproducible. Never
    reuse a nonce across two different digests with the same key.
    Returns (r, s, y_parity) with low-s normalisation.
    """
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    if not 0 < nonce < N:
        raise ValueError("nonce out of range")
    r_point = _mul(nonce, G)
    if r_point is None:
        raise ValueError("invalid nonce")
    r = r_point[0] % N
    if r == 0:
        raise ValueError("invalid nonce")
    e = int.from_bytes(digest, "big")
    s = (_inv(nonce, N) * (e + r * private_key)) % N
    if s == 0:
        raise ValueError("invalid nonce")
    y_parity = r_point[1] & 1
    if s > N // 2:
        s = N - s
        y_parity ^= 1
    return r, s, y_parity
