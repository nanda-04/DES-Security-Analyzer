from flask import Flask, render_template, request

from des.utils import (
    binary_to_hex,
    text_to_64bit,
    binary_64bit_to_text
)

from des.key_schedule import generate_round_keys
from des.des_algorithm import encrypt_block, decrypt_block

from des.security_analysis import analyze_key_change


app = Flask(__name__)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# TEXT ENCRYPTION
# =========================================================

@app.route("/encrypt-text", methods=["POST"])
def encrypt_text():

    plaintext = request.form["plaintext"]
    key = request.form["key"]

    try:

        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")

        if not key:
            raise ValueError("Key cannot be empty.")

        if len(plaintext) > 8:
            raise ValueError(
                "For this educational version, plaintext must be 8 characters or fewer."
            )

        if len(key) > 8:
            raise ValueError(
                "For this educational version, key must be 8 characters or fewer."
            )

        plaintext_binary = text_to_64bit(plaintext)
        key_binary = text_to_64bit(key)

        round_keys = generate_round_keys(key_binary)

        cipher_binary, rounds = encrypt_block(
            plaintext_binary,
            round_keys
        )

        ciphertext = binary_to_hex(cipher_binary)

        return render_template(
            "index.html",
            mode="Text Encryption",
            plaintext=plaintext,
            key=key,
            ciphertext=ciphertext,
            rounds=rounds
        )

    except ValueError as error:

        return render_template(
            "index.html",
            error=str(error)
        )


# =========================================================
# TEXT DECRYPTION
# =========================================================

@app.route("/decrypt-text", methods=["POST"])
def decrypt_text():

    ciphertext = request.form["ciphertext"].strip().upper()
    key = request.form["key"]

    try:

        if len(ciphertext) != 16:
            raise ValueError(
                "Ciphertext must contain exactly 16 hexadecimal characters."
            )

        if not key:
            raise ValueError("Key cannot be empty.")

        if len(key) > 8:
            raise ValueError(
                "For this educational version, key must be 8 characters or fewer."
            )

        ciphertext_binary = bin(
            int(ciphertext, 16)
        )[2:].zfill(64)

        key_binary = text_to_64bit(key)

        round_keys = generate_round_keys(key_binary)

        plaintext_binary, rounds = decrypt_block(
            ciphertext_binary,
            round_keys
        )

        decrypted_text = binary_64bit_to_text(
            plaintext_binary
        )

        return render_template(
            "index.html",
            mode="Text Decryption",
            ciphertext=ciphertext,
            key=key,
            decrypted_text=decrypted_text,
            rounds=rounds
        )

    except (ValueError, TypeError):

        return render_template(
            "index.html",
            error="Invalid ciphertext or key."
        )


# =========================================================
# HEXADECIMAL ENCRYPTION
# =========================================================

@app.route("/encrypt", methods=["POST"])
def encrypt():

    plaintext = request.form["plaintext"].strip().upper()
    key = request.form["key"].strip().upper()

    try:

        if len(plaintext) != 16 or len(key) != 16:
            raise ValueError

        plaintext_binary = bin(
            int(plaintext, 16)
        )[2:].zfill(64)

        key_binary = bin(
            int(key, 16)
        )[2:].zfill(64)

        round_keys = generate_round_keys(key_binary)

        cipher_binary, rounds = encrypt_block(
            plaintext_binary,
            round_keys
        )

        ciphertext = binary_to_hex(cipher_binary)

        return render_template(
            "index.html",
            mode="Hexadecimal Encryption",
            plaintext=plaintext,
            key=key,
            ciphertext=ciphertext,
            rounds=rounds
        )

    except ValueError:

        return render_template(
            "index.html",
            error="Please enter exactly 16 hexadecimal characters."
        )


# =========================================================
# HEXADECIMAL DECRYPTION
# =========================================================

@app.route("/decrypt", methods=["POST"])
def decrypt():

    ciphertext = request.form["ciphertext"].strip().upper()
    key = request.form["key"].strip().upper()

    try:

        if len(ciphertext) != 16 or len(key) != 16:
            raise ValueError

        ciphertext_binary = bin(
            int(ciphertext, 16)
        )[2:].zfill(64)

        key_binary = bin(
            int(key, 16)
        )[2:].zfill(64)

        round_keys = generate_round_keys(key_binary)

        plaintext_binary, rounds = decrypt_block(
            ciphertext_binary,
            round_keys
        )

        decrypted_text = binary_to_hex(
            plaintext_binary
        )

        return render_template(
            "index.html",
            mode="Hexadecimal Decryption",
            ciphertext=ciphertext,
            key=key,
            decrypted_text=decrypted_text,
            rounds=rounds
        )

    except ValueError:

        return render_template(
            "index.html",
            error="Please enter exactly 16 hexadecimal characters."
        )


# =========================================================
# SECURITY ANALYSIS
# =========================================================

@app.route("/security-analysis", methods=["POST"])
def security_analysis():

    plaintext = request.form["analysis_plaintext"]
    original_key = request.form["original_key"]
    changed_key = request.form["changed_key"]

    try:

        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")

        if len(plaintext) > 8:
            raise ValueError(
                "Plaintext must contain 8 characters or fewer."
            )

        if len(original_key) > 8:
            raise ValueError(
                "Original key must contain 8 characters or fewer."
            )

        if len(changed_key) > 8:
            raise ValueError(
                "Changed key must contain 8 characters or fewer."
            )

        if original_key == changed_key:
            raise ValueError(
                "Original key and changed key must be different."
            )

        result = analyze_key_change(
            plaintext,
            original_key,
            changed_key
        )

        return render_template(
            "index.html",
            analysis=result
        )

    except ValueError as error:

        return render_template(
            "index.html",
            error=str(error)
        )


# =========================================================
# START FLASK
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)