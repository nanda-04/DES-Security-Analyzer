from .utils import text_to_64bit, binary_to_hex
from .key_schedule import generate_round_keys
from .des_algorithm import encrypt_block


def encrypt_text_for_analysis(plaintext, key):
    """
    Encrypt one 64-bit text block using DES.
    """

    plaintext_binary = text_to_64bit(plaintext)
    key_binary = text_to_64bit(key)

    round_keys = generate_round_keys(key_binary)

    cipher_binary, rounds = encrypt_block(
        plaintext_binary,
        round_keys
    )

    ciphertext = binary_to_hex(cipher_binary)

    return ciphertext, cipher_binary, rounds


def count_different_bits(binary1, binary2):
    """
    Count the number of different bits
    between two binary strings.
    """

    return sum(
        bit1 != bit2
        for bit1, bit2 in zip(binary1, binary2)
    )


def calculate_avalanche_effect(binary1, binary2):
    """
    Calculate avalanche percentage.
    """

    changed_bits = count_different_bits(
        binary1,
        binary2
    )

    total_bits = len(binary1)

    percentage = (
        changed_bits / total_bits
    ) * 100

    return changed_bits, total_bits, percentage


def analyze_key_change(
    plaintext,
    original_key,
    changed_key
):
    """
    Compare DES encryption using two different keys.
    """

    ciphertext1, binary1, rounds1 = encrypt_text_for_analysis(
        plaintext,
        original_key
    )

    ciphertext2, binary2, rounds2 = encrypt_text_for_analysis(
        plaintext,
        changed_key
    )

    changed_bits, total_bits, percentage = calculate_avalanche_effect(
        binary1,
        binary2
    )

    return {
        "plaintext": plaintext,

        "original_key": original_key,
        "changed_key": changed_key,

        "ciphertext1": ciphertext1,
        "ciphertext2": ciphertext2,

        "changed_bits": changed_bits,
        "total_bits": total_bits,

        "avalanche_percentage": round(
            percentage,
            2
        ),

        "rounds1": rounds1,
        "rounds2": rounds2
    }