"""Minimal QR code generator (version 5, error correction L, byte mode, mask 0).

Standard library only — no dependency, no external service (constraint C-3/C-4).
Capacity: 106 bytes, enough for an absolute verification URL such as
`https://host:port/verify.html?code=XXXX-XXXX-XXXX-XXXX-XXXX`. Longer input is refused
rather than truncated, because a truncated URL would scan to the wrong page.
"""
from __future__ import annotations

# --- Galois field arithmetic for Reed-Solomon ------------------------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_divisor(degree: int) -> list[int]:
    """Generator polynomial coefficients, highest power first, leading 1 omitted."""
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    divisor = _rs_divisor(ec_len)
    remainder = [0] * ec_len
    for byte in data:
        factor = byte ^ remainder.pop(0)
        remainder.append(0)
        for i, coefficient in enumerate(divisor):
            remainder[i] ^= _gf_mul(coefficient, factor)
    return remainder


# --- QR version 5-L parameters (one block) ---------------------------------
VERSION = 5
SIZE = 37                # 17 + 4 * version
TOTAL_CODEWORDS = 134
EC_CODEWORDS = 26
DATA_CODEWORDS = 108     # 134 - 26
ALIGNMENT_CENTRES = [6, 30]
FORMAT_BITS_L_MASK0 = 0b111011111000100     # EC level L, mask pattern 0
MAX_PAYLOAD = DATA_CODEWORDS - 2            # 4-bit mode + 8-bit count, rounded to bytes


def _place_patterns(matrix: list[list[int | None]], size: int) -> None:
    def finder(row: int, col: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = row + r, col + c
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                if r in (-1, 7) or c in (-1, 7):
                    matrix[rr][cc] = 0                # separator
                elif r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4):
                    matrix[rr][cc] = 1
                else:
                    matrix[rr][cc] = 0

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(size):                    # timing patterns
        value = 1 if i % 2 == 0 else 0
        if matrix[6][i] is None:
            matrix[6][i] = value
        if matrix[i][6] is None:
            matrix[i][6] = value

    for r in ALIGNMENT_CENTRES:
        for c in ALIGNMENT_CENTRES:
            if (r, c) in {(6, 6), (6, size - 7), (size - 7, 6)}:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    matrix[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0


def _place_format(matrix: list[list[int | None]], size: int) -> None:
    """Both copies of the 15 format bits (ISO/IEC 18004 §7.9), bit 0 = least significant."""
    bit = [(FORMAT_BITS_L_MASK0 >> i) & 1 for i in range(15)]
    for i in range(6):                       # first copy, around the top-left finder
        matrix[i][8] = bit[i]
    matrix[7][8] = bit[6]
    matrix[8][8] = bit[7]
    matrix[8][7] = bit[8]
    for i in range(9, 15):
        matrix[8][14 - i] = bit[i]
    for i in range(8):                       # second copy, split top-right / bottom-left
        matrix[8][size - 1 - i] = bit[i]
    for i in range(8, 15):
        matrix[size - 15 + i][8] = bit[i]
    matrix[size - 8][8] = 1                  # dark module


def _encode_bytes(text: str) -> list[int]:
    payload = text.encode("utf-8")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"QR payload is {len(payload)} bytes; version {VERSION}-L holds "
                         f"at most {MAX_PAYLOAD}")
    bits: list[int] = []
    bits += [0, 1, 0, 0]                                      # byte mode
    bits += [(len(payload) >> i) & 1 for i in range(7, -1, -1)]
    for byte in payload:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]
    capacity = DATA_CODEWORDS * 8
    bits += [0] * min(4, capacity - len(bits))                # terminator
    while len(bits) % 8:
        bits.append(0)
    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    index = 0
    while len(codewords) < DATA_CODEWORDS:
        codewords.append(pad[index % 2])
        index += 1
    return codewords + _rs_encode(codewords, EC_CODEWORDS)


def build_matrix(text: str) -> list[list[int]]:
    size = SIZE
    matrix: list[list[int | None]] = [[None] * size for _ in range(size)]
    _place_patterns(matrix, size)
    _place_format(matrix, size)

    codewords = _encode_bytes(text)
    bits = [(byte >> i) & 1 for byte in codewords for i in range(7, -1, -1)]

    # Every function module is already set, so any cell still None belongs to the data region.
    index = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if matrix[row][c] is not None:
                    continue
                bit = bits[index] if index < len(bits) else 0  # remainder bits are 0
                index += 1
                if (row + c) % 2 == 0:                        # mask pattern 0
                    bit ^= 1
                matrix[row][c] = bit
        upward = not upward
        col -= 2

    return [[cell or 0 for cell in row] for row in matrix]


def qr_svg(text: str, module: int = 8, quiet_zone: int = 4) -> str:
    matrix = build_matrix(text)
    size = len(matrix)
    dimension = (size + quiet_zone * 2) * module
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dimension}" height="{dimension}" '
        f'viewBox="0 0 {dimension} {dimension}" role="img" '
        f'aria-label="QR code linking to the product verification page">',
        f'<rect width="{dimension}" height="{dimension}" fill="#ffffff"/>',
    ]
    for r, row in enumerate(matrix):
        for c, cell in enumerate(row):
            if cell:
                x = (c + quiet_zone) * module
                y = (r + quiet_zone) * module
                parts.append(f'<rect x="{x}" y="{y}" width="{module}" height="{module}" '
                             f'fill="#111111"/>')
    parts.append("</svg>")
    return "".join(parts)
