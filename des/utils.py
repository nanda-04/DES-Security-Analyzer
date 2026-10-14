def text_to_binary(text):
    """
    Convert text into its 8-bit binary representation.
    """
    return ''.join(
        format(ord(char), '08b')
        for char in text
    )


def binary_to_text(binary):
    """
    Convert binary data back into text.
    """
    chars = []

    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]

        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))

    return ''.join(chars)


def hex_to_binary(hex_string):
    """
    Convert hexadecimal string to binary.
    """
    return bin(int(hex_string, 16))[2:].zfill(
        len(hex_string) * 4
    )


def binary_to_hex(binary):
    """
    Convert binary string to hexadecimal.
    """
    return hex(int(binary, 2))[2:].upper().zfill(
        len(binary) // 4
    )


def xor_bits(a, b):
    """
    Perform XOR between two binary strings.
    """
    return ''.join(
        '0' if x == y else '1'
        for x, y in zip(a, b)
    )


def permute(bits, table):
    """
    Rearrange bits according to a DES permutation table.

    DES tables use 1-based positions,
    while Python strings use 0-based indexing.
    """
    return ''.join(
        bits[position - 1]
        for position in table
    )


def text_to_64bit(text):
    """
    Convert ASCII text into one 64-bit DES block.

    DES operates on 64-bit blocks,
    so the input can contain at most 8 characters.

    If fewer than 8 characters are entered,
    null characters are added as padding.
    """

    if len(text) > 8:
        raise ValueError(
            "Text must contain at most 8 characters."
        )

    # Pad text to exactly 8 characters
    text = text.ljust(8, '\0')

    return ''.join(
        format(ord(char), '08b')
        for char in text
    )


def binary_64bit_to_text(binary):
    """
    Convert a 64-bit binary block back into text.

    Padding null characters are removed.
    """

    text = binary_to_text(binary)

    return text.rstrip('\0')