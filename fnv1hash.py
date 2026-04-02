#  FNV-1a HASH 
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