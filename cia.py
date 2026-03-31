import base64
import math

ALPHABET_SIZE = 26
HASH_HEX_LEN  = 64   # 32 bytes * 2 hex chars each


# ---------------------------------------------
#  HELPERS
# ---------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    if math.gcd(a, m) != 1:
        raise ValueError(
            f"Key {a} has no modular inverse mod {m}. "
            "Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25"
        )
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


# ---------------------------------------------
#  FNV-1a HASH  (no built-in hash library)
# ---------------------------------------------

def fnv1a_hash(data: str) -> bytes:

    MASK64   = 0xFFFFFFFFFFFFFFFF
    CONSTANT = 0x9E3779B97F4A7C15

    def rotl64(x, n):
        return ((x << n) | (x >> (64 - n))) & MASK64

    OFFSETS = [
        14695981039346656037,
        14695981039346656037 ^ 0xDEADBEEFDEADBEEF,
        14695981039346656037 ^ 0xCAFEBABECAFEBABE,
        14695981039346656037 ^ 0x0123456789ABCDEF,
    ]

    acc = list(OFFSETS)
    for byte in (ord(ch) for ch in data):
        for lane in range(4):
            acc[lane] ^= byte
            acc[lane]  = rotl64(acc[lane], 11)
            acc[lane] ^= (acc[lane] >> 33)
            acc[lane]  = (acc[lane] + CONSTANT) & MASK64

    result = b''
    for a in acc:
        result += a.to_bytes(8, byteorder='big')
    return result


def compute_hash(ciphertext: str, salt: str) -> str:
    """fnv1a_hash(salt + ciphertext) -> hex string (64 chars)."""
    return fnv1a_hash(salt + ciphertext).hex()


# ---------------------------------------------
#  MULTIPLICATIVE CIPHER
# ---------------------------------------------

def mult_encrypt(plaintext: str, key: int) -> str:
    if math.gcd(key, ALPHABET_SIZE) != 1:
        raise ValueError(f"Key {key} must be coprime to {ALPHABET_SIZE}.")
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(((ord(ch) - base) * key % ALPHABET_SIZE) + base))
        else:
            result.append(ch)
    return "".join(result)


def mult_decrypt(ciphertext: str, key: int) -> str:
    inv = mod_inverse(key, ALPHABET_SIZE)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(((ord(ch) - base) * inv % ALPHABET_SIZE) + base))
        else:
            result.append(ch)
    return "".join(result)


# ---------------------------------------------
#  ENCRYPTION PIPELINE  (Sender)
# ---------------------------------------------

def encrypt_and_transmit(plaintext: str, mult_key: int, salt: str) -> dict:
    # Step 1 -- multiplicative cipher
    ciphered = mult_encrypt(plaintext, mult_key)

    # Step 2 -- hash(salt + ciphertext)
    hash_hex = compute_hash(ciphered, salt)

    # Step 3 -- transmit: ciphertext + hash
    transmission = ciphered + hash_hex

    return {
        "plaintext"   : plaintext,
        "ciphered"    : ciphered,
        "salt"        : salt,
        "hash_hex"    : hash_hex,
        "transmission": transmission,
    }


# ---------------------------------------------
#  DECRYPTION PIPELINE  (Receiver)
# ---------------------------------------------

def receive_and_decrypt(transmission: str, mult_key: int, salt: str) -> dict:
    # Step 1 -- split: last 64 chars = hash hex, rest = ciphertext
    recv_hash_hex = transmission[-HASH_HEX_LEN:]
    ciphered      = transmission[:-HASH_HEX_LEN]

    # Step 2 -- re-hash(salt + ciphertext) and compare
    expected_hash_hex = compute_hash(ciphered, salt)
    is_valid          = recv_hash_hex == expected_hash_hex

    # Step 3 -- decrypt only if valid
    plaintext = mult_decrypt(ciphered, mult_key) if is_valid else None

    return {
        "transmission" : transmission,
        "ciphered"     : ciphered,
        "recv_hash_hex": recv_hash_hex,
        "exp_hash_hex" : expected_hash_hex,
        "integrity"    : is_valid,
        "plaintext"    : plaintext,
    }




if __name__ == "__main__":
    MULT_KEY  = int(input("Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25:: "))
    SALT      = "s3cr3t!"
    plaintext = input("Plaintext: ")

    sep = "=" * 62
    print(sep)
    print("  MULTIPLICATIVE CIPHER  +  FNV-1a HASH")
    print("  Format: ciphertext + fnv1a(salt + ciphertext)")
    print(sep)

    # -- SENDER --
    print("\n[ SENDER ]")
    s = encrypt_and_transmit(plaintext, MULT_KEY, SALT)
    print(f"  Plaintext    : {s['plaintext']}")
    print(f"  Mult key     : {MULT_KEY}  (inverse mod 26 = {mod_inverse(MULT_KEY, 26)})")
    print(f"  Ciphered     : {s['ciphered']}")
    print(f"  Salt         : {s['salt']}")
    print(f"  Hash (hex)   : {s['hash_hex']}")
    print(f"  Transmission : {s['transmission']}")

    # -- RECEIVER --
    print("\n[ RECEIVER ]")
    r = receive_and_decrypt(s['transmission'], MULT_KEY, SALT)
    print(f"  Ciphered     : {r['ciphered']}")
    print(f"  Recv hash    : {r['recv_hash_hex']}")
    print(f"  Exp  hash    : {r['exp_hash_hex']}")
    print(f"  Integrity    : {'VALID' if r['integrity'] else 'TAMPERED'}")
    print(f"  Plaintext    : {r['plaintext']}")