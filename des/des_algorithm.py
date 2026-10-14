from .tables import IP, FP, E, P, S_BOXES
from .utils import permute, xor_bits


def s_box_substitution(bits):
    """
    Convert 48-bit input into 32-bit output
    using the eight DES S-boxes.
    """

    output = ""

    # Split 48 bits into eight 6-bit blocks
    blocks = [
        bits[i:i + 6]
        for i in range(0, 48, 6)
    ]

    for i, block in enumerate(blocks):

        # First and last bits determine the row
        row = int(block[0] + block[5], 2)

        # Middle four bits determine the column
        column = int(block[1:5], 2)

        # Look up value in S-box
        value = S_BOXES[i][row][column]

        # Convert to 4-bit binary
        output += format(value, "04b")

    return output


def feistel_function(right, round_key):
    """
    DES Feistel function.

    32-bit right half
        ↓
    Expansion
        ↓
    XOR with 48-bit round key
        ↓
    S-box substitution
        ↓
    P permutation
        ↓
    32-bit result
    """

    # Expansion: 32 bits -> 48 bits
    expanded = permute(right, E)

    # XOR with round key
    xored = xor_bits(expanded, round_key)

    # S-box substitution: 48 bits -> 32 bits
    substituted = s_box_substitution(xored)

    # P permutation
    result = permute(substituted, P)

    return result


def encrypt_block(block, round_keys):
    """
    Encrypt one 64-bit block using DES.

    Returns:
        ciphertext
        round information
    """

    # Initial permutation
    permuted_block = permute(block, IP)

    # Split into two 32-bit halves
    left = permuted_block[:32]
    right = permuted_block[32:]

    rounds = []

    # 16 Feistel rounds
    for round_number in range(16):

        previous_left = left
        previous_right = right

        # Feistel operation
        f_result = feistel_function(
            right,
            round_keys[round_number]
        )

        # New left = previous right
        left = previous_right

        # New right = previous left XOR F(right, key)
        right = xor_bits(previous_left, f_result)

        rounds.append({
            "round": round_number + 1,
            "left": left,
            "right": right,
            "round_key": round_keys[round_number]
        })

    # Swap the final halves
    combined = right + left

    # Final permutation
    ciphertext = permute(combined, FP)

    return ciphertext, rounds


def decrypt_block(block, round_keys):
    """
    Decrypt one 64-bit block using DES.

    DES decryption uses the same Feistel structure,
    but the round keys are applied in reverse order.
    """

    plaintext, rounds = encrypt_block(
        block,
        round_keys[::-1]
    )

    return plaintext, rounds