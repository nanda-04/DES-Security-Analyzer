from des.utils import text_to_64bit
from des.key_schedule import generate_round_keys


key1 = "SECURITY"
key2 = "SECURITX"


binary_key1 = text_to_64bit(key1)
binary_key2 = text_to_64bit(key2)


round_keys1 = generate_round_keys(binary_key1)
round_keys2 = generate_round_keys(binary_key2)


print("========== KEY TEST ==========")

print("Key 1:", key1)
print("Key 2:", key2)

print()

print("Binary Key 1:")
print(binary_key1)

print()

print("Binary Key 2:")
print(binary_key2)

print()

print("========== ROUND KEY COMPARISON ==========")

for i in range(16):

    same = round_keys1[i] == round_keys2[i]

    print(
        f"Round {i + 1:2}: "
        f"{'SAME' if same else 'DIFFERENT'}"
    )

print()

print("Round 1 Key 1:")
print(round_keys1[0])

print()

print("Round 1 Key 2:")
print(round_keys2[0])

print("==========================================")