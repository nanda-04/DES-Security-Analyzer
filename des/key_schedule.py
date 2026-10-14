from .tables import PC1, PC2, SHIFT_SCHEDULE
from .utils import permute


def left_shift(bits, shifts):
    """
    Perform a circular left shift.
    """
    return bits[shifts:] + bits[:shifts]


def generate_round_keys(key):
    """
    Generate the 16 DES round keys.

    Input:
        key - 64-bit binary key

    Output:
        List containing 16 round keys,
        each of 48 bits.
    """

    # Step 1: Apply PC-1
    key_56 = permute(key, PC1)

    # Step 2: Split into two 28-bit halves
    C = key_56[:28]
    D = key_56[28:]

    round_keys = []

    # Step 3: Generate 16 round keys
    for shift in SHIFT_SCHEDULE:

        # Left circular shifts
        C = left_shift(C, shift)
        D = left_shift(D, shift)

        # Combine C and D
        combined = C + D

        # Apply PC-2 to produce 48-bit round key
        round_key = permute(combined, PC2)

        round_keys.append(round_key)

    return round_keys