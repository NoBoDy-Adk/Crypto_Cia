Multiplicative Cipher for encryption
 A custom hash function (FNV-1a based, without using any built-in hash libraries)
 A fixed salt for integrity verification

multiplicative cipher 

Encryption:
C = (P × key) mod 26

Decryption:
P = (C × key⁻¹) mod 26

Constraints:
- Key must be coprime with 26
- Compute modular inverse using Extended Euclidean Algorithm
- Preserve case (uppercase/lowercase)
- Non-alphabet characters should remain unchanged

FNV-1a  hash function

- Use 4 parallel 64-bit accumulators
- Initialize each with different offset values
- For each character:
   - XOR with accumulator
   - Apply bit rotation (left rotate)
   - Apply XOR shift
   - Add a constant value
- Combine all accumulators into a 32-byte output
- Return hash as a hexadecimal string (64 characters)

encryption workflow

Plaintext
→ Apply multiplicative cipher using a valid key (coprime with 26)
→ Generate hash using:
   hash = fnv1a(salt + ciphertext)
→ Convert hash to hexadecimal string
→ Concatenate:
   transmission = ciphertext + hash
→ Transmit the final string


 decryption workflow

Received transmission
→ Split into:
   ciphertext = transmission[:-64]
   hash       = transmission[-64:]
→ Recompute hash:
   expected_hash = fnv1a(salt + ciphertext)
→ Compare hashes:
   if equal → proceed
   else → reject as tampered
→ If valid:
   decrypt ciphertext using multiplicative cipher inverse
→ Return plaintext