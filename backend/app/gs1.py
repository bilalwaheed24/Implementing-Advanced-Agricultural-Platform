"""GS1 identifier checks (GS1 General Specifications §7.9, mod-10 check digit).

A GTIN is only valid when its last digit equals the check digit computed from the others:
weights 3 and 1 alternate from the rightmost data digit. A typo in one digit, or swapping
two neighbouring digits, almost always changes the result, which is why GS1 uses it.
"""
from __future__ import annotations

GTIN_LENGTHS = {8, 12, 13, 14}      # GTIN-8, GTIN-12 (UPC-A), GTIN-13 (EAN), GTIN-14


def check_digit(data_digits: str) -> int:
    """Check digit for a string of digits that does not yet include one."""
    total = 0
    for position, char in enumerate(reversed(data_digits)):
        total += int(char) * (3 if position % 2 == 0 else 1)
    return (10 - total % 10) % 10


def is_valid_gtin(value: str) -> bool:
    return (value.isdigit() and len(value) in GTIN_LENGTHS
            and check_digit(value[:-1]) == int(value[-1]))


def with_check_digit(data_digits: str) -> str:
    """Append the correct check digit, e.g. for generating demonstration identifiers."""
    return data_digits + str(check_digit(data_digits))
