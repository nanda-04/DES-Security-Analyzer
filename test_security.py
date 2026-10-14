from des.security_analysis import analyze_key_change
from des.utils import text_to_64bit


# -------------------------------------------------
# INPUT DATA
# -------------------------------------------------

plaintext = "NETWORK"

original_key = "SECURITY"

# Changed key
# We are changing Y -> Z
changed_key = "SECURITZ"


# -------------------------------------------------
# SHOW KEY INFORMATION
# -------------------------------------------------

print("========== KEY COMPARISON ==========")

print("Original Key :", original_key)
print("Changed Key  :", changed_key)

print()

print("Original Key Binary:")
print(text_to_64bit(original_key))

print()

print("Changed Key Binary:")
print(text_to_64bit(changed_key))

print()

print("====================================")
print()


# -------------------------------------------------
# DES SECURITY ANALYSIS
# -------------------------------------------------

result = analyze_key_change(
    plaintext,
    original_key,
    changed_key
)


# -------------------------------------------------
# DISPLAY RESULTS
# -------------------------------------------------

print("========== DES SECURITY ANALYSIS ==========")

print("Plaintext       :", result["plaintext"])

print()

print("Original Key    :", result["original_key"])
print("Changed Key     :", result["changed_key"])

print()

print("Ciphertext 1    :", result["ciphertext1"])
print("Ciphertext 2    :", result["ciphertext2"])

print()

print("Changed Bits    :", result["changed_bits"])
print("Total Bits      :", result["total_bits"])

print()

print(
    "Avalanche Effect:",
    result["avalanche_percentage"],
    "%"
)

print()

print("==========================================")