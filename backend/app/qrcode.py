"""Minimal QR code generator (version 3, error correction L, byte mode).

Standard library only — no dependency, no external service (constraint C-3/C-4).
Capacity: 53 bytes, which comfortably covers a verification URL.
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


def _rs_generator(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        poly.append(0)
        for j in range(len(poly) - 1, 0, -1):
            poly[j] = poly[j - 1] ^ _gf_mul(poly[j], _EXP[i])
        poly[0] = _gf_mul(poly[0], _EXP[i])
    return poly


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    generator = _rs_generator(ec_len)
    remainder = [0] * ec_len
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        for i in range(ec_len):
            remainder[i] ^= _gf_mul(generator[i + 1] if i + 1 < len(generator) else 0, factor)
    return remainder


# --- QR version 3-L parameters ---------------------------------------------
VERSION = 3
SIZE = 29                # 17 + 4 * version
TOTAL_CODEWORDS = 70
EC_CODEWORDS = 15
DATA_CODEWORDS = 55      # 70 - 15
ALIGNMENT_CENTRES = [6, 22]
FORMAT_BITS_L_MASK0 = 0b111011111000100     # EC level L, mask pattern 0


def _reserved(size: int) -> list[list[bool]]:
    reserved = [[False] * size for _ in range(size)]

    def block(row: int, col: int, height: int, width: int) -> None:
        for r in range(row, min(row + height, size)):
            for c in range(col, min(col + width, size)):
                if r >= 0 and c >= 0:
                    reserved[r][c] = True

    block(0, 0, 9, 9)                        # top-left finder + format
    block(0, size - 8, 9, 8)                 # top-right finder + format
    block(size - 8, 0, 8, 9)                 # bottom-left finder + format
    for r in ALIGNMENT_CENTRES:
        for c in ALIGNMENT_CENTRES:
            if (r, c) == (6, 6) or (r, c) == (6, size - 7) or (r, c) == (size - 7, 6):
                continue
            block(r - 2, c - 2, 5, 5)
    for i in range(size):                    # timing patterns
        reserved[6][i] = True
        reserved[i][6] = True
    return reserved


def _place_patterns(matrix: list[list[int]], size: int) -> None:
    def finder(row: int, col: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = row + r, col + c
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                if r in (-1, 7) or c in (-1, 7):
                    matrix[rr][cc] = 0
                elif r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4):
                    matrix[rr][cc] = 1
                else:
                    matrix[rr][cc] = 0

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(size):
        value = 1 if i % 2 == 0 else 0
        if matrix[6][i] is None:
            matrix[6][i] = value
        if matrix[i][6] is None:
            matrix[i][6] = value

    for r in ALIGNMENT_CENTRES:
        for c in ALIGNMENT_CENTRES:
            if (r, c) in {(6, 6), (6, SIZE - 7), (SIZE - 7, 6)}:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    matrix[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0

    matrix[size - 8][8] = 1                  # dark module


def _place_format(matrix: list[list[int]], size: int) -> None:
    bits = [(FORMAT_BITS_L_MASK0 >> i) & 1 for i in range(15)]
    coords_a = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
                (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    for bit, (r, c) in zip(bits, coords_a):
        matrix[r][c] = bit
    coords_b = [(size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8), (size - 5, 8),
                (size - 6, 8), (size - 7, 8), (8, size - 8), (8, size - 7), (8, size - 6),
                (8, size - 5), (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1)]
    for bit, (r, c) in zip(bits, coords_b):
        matrix[r][c] = bit


def _encode_bytes(text: str) -> list[int]:
    payload = text.encode("utf-8")
    if len(payload) > DATA_CODEWORDS - 2:
        payload = payload[:DATA_CODEWORDS - 2]
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
    reserved = _reserved(size)

    codewords = _encode_bytes(text)
    bits = [(byte >> i) & 1 for byte in codewords for i in range(7, -1, -1)]

    index = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if reserved[row][c] or matrix[row][c] is not None:
                    continue
                bit = bits[index] if index < len(bits) else 0
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
