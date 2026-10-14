from des.utils import text_to_binary, binary_to_hex
from des.key_schedule import generate_round_keys
from des.des_algorithm import encrypt_block, decrypt_block


# 64-bit plaintext
plaintext = "0123456789ABCDEF"

# 64-bit DES key
key = "133457799BBCDFF1"


# Convert hexadecimal values to binary
plaintext_binary = bin(int(plaintext, 16))[2:].zfill(64)
key_binary = bin(int(key, 16))[2:].zfill(64)


print("Plaintext :", plaintext)
print("Key       :", key)

# Generate 16 round keys
round_keys = generate_round_keys(key_binary)

print("\nRound Keys:")
for i, round_key in enumerate(round_keys, start=1):
    print(f"Round {i:2}: {binary_to_hex(round_key)}")


# Encrypt
cipher_binary, rounds = encrypt_block(
    plaintext_binary,
    round_keys
)

ciphertext = binary_to_hex(cipher_binary)

print("\nCiphertext:", ciphertext)


# Decrypt
decrypted_binary, _ = decrypt_block(
    cipher_binary,
    round_keys
)

decrypted_text = binary_to_hex(decrypted_binary)

print("Decrypted :", decrypted_text)


# Verify
if decrypted_text == plaintext:
    print("\nDES Encryption/Decryption: SUCCESS")
else:
    print("\nDES Encryption/Decryption: FAILED")