"""Keccak-256 and the EIP-55 address checksum.

Solidity 0.8 rejects an address literal whose letter case does not match the
EIP-55 checksum, and the checksum is derived from keccak-256 of the lowercase
hex address.  Neither Python's standard library nor Node's `crypto` module
provides keccak-256: `hashlib` offers SHA3-256, which is a different padding
construction and produces a different digest, and `crypto.getHashes()` lists
`sha3-256` rather than the original Keccak padding that Ethereum uses.

The permutation is therefore implemented here.  It is the standard Keccak-f
[1600] round function with the 0x01 domain separator Ethereum uses, and it is
checked against the published test vectors in the module's own tests.
"""

from __future__ import annotations

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_MASK64 = (1 << 64) - 1


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state: list[list[int]]) -> list[list[int]]:
    for round_constant in _ROUND_CONSTANTS:
        # Theta
        column_parity = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
            for x in range(5)
        ]
        for x in range(5):
            d = column_parity[(x - 1) % 5] ^ _rotl(column_parity[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= d
        # Rho and Pi
        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotated[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _ROTATION_OFFSETS[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x][y] = rotated[x][y] ^ ((~rotated[(x + 1) % 5][y] & _MASK64) & rotated[(x + 2) % 5][y])
        # Iota
        state[0][0] ^= round_constant
    return state


def keccak256(data: bytes) -> bytes:
    """The Keccak-256 digest Ethereum uses, distinct from SHA3-256."""
    rate = 136
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for index in range(rate // 8):
            lane = int.from_bytes(block[index * 8:index * 8 + 8], "little")
            state[index % 5][index // 5] ^= lane
        state = _keccak_f(state)
    output = bytearray()
    for index in range(4):
        output += state[index % 5][index // 5].to_bytes(8, "little")
    return bytes(output)


def to_checksum_address(address: str) -> str:
    """Return the EIP-55 checksummed form of a 20-byte hex address."""
    text = address.lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 40 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("address is not a 20-byte hex value")
    digest = keccak256(text.encode("ascii")).hex()
    return "0x" + "".join(
        character.upper() if character in "abcdef" and int(digest[index], 16) >= 8 else character
        for index, character in enumerate(text)
    )
