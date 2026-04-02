


"how to run:
   python testcases.py
"




Multiplicative Cipher for encryption
 A custom hash function (FNV-1a based, without using any built-in hash libraries)
 A fixed salt for integrity verification

multiplicative cipher 

Encryption:
C = (P × key) mod 26

Decryption:
P = (C × key⁻¹) mod 26

Constraints:
->Key must be coprime with 26
->Compute modular inverse using Extended Euclidean Algorithm
->Preserve case (uppercase/lowercase)
->Non-alphabet characters should remain unchanged

FNV-1a  hash function

->Use 4 parallel 64-bit accumulators
->Initialize each with different offset values
->For each character:
   ->XOR with accumulator
   ->Apply bit rotation (left rotate)
   ->Apply XOR shift
   ->Add a constant value
->Combine all accumulators into a 32-byte output
->Return hash as a hexadecimal string (64 characters)

encryption workflow

Plaintext
->Apply multiplicative cipher using a valid key (coprime with 26)
->Generate hash using:
   hash = fnv1a(salt + ciphertext)
->Convert hash to hexadecimal string
->Concatenate:
   transmission = ciphertext + hash
->Transmit the final string


 decryption workflow

Received transmission
->Split into:
   ciphertext,hash
->Recompute hash:
   expected_hash = fnv1a(salt + ciphertext)
->Compare hashes:
->decrypt ciphertext using multiplicative cipher inverse
->Return plaintext

example:

Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25:: 9
Plaintext: hello 123
  MULTIPLICATIVE CIPHER  

[ SENDER ]
  Plaintext    : hello 123
  Mult key     : 9  (inverse mod 26 = 3)
  Ciphered     : lkvvw 123
  Salt         : s3cr3t!
  Hash (hex)   : a442a6121e60fd80cf0fa2bad903a80c63a3674fba42d17fd419a7f29416e31a
  Transmission : lkvvw 123a442a6121e60fd80cf0fa2bad903a80c63a3674fba42d17fd419a7f29416e31a

[ RECEIVER ]
  Ciphered     : lkvvw 123
  Recv hash    : a442a6121e60fd80cf0fa2bad903a80c63a3674fba42d17fd419a7f29416e31a
  Exp  hash    : a442a6121e60fd80cf0fa2bad903a80c63a3674fba42d17fd419a7f29416e31a
  Integrity    : VALID
  Plaintext    : hello 123


  Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25:: 7
Plaintext: hello123
  MULTIPLICATIVE CIPHER  

[ SENDER ]
  Plaintext    : hello123
  Mult key     : 7  (inverse mod 26 = 15)
  Ciphered     : xczzu123
  Salt         : s3cr3t!
  Hash (hex)   : 1511e08584a90af2d2e7b963595d2533943945b7b68ce574c32737dc79def9e3
  Transmission : xczzu1231511e08584a90af2d2e7b963595d2533943945b7b68ce574c32737dc79def9e3

[ RECEIVER ]
  Ciphered     : xczzu123
  Recv hash    : 1511e08584a90af2d2e7b963595d2533943945b7b68ce574c32737dc79def9e3
  Exp  hash    : 1511e08584a90af2d2e7b963595d2533943945b7b68ce574c32737dc79def9e3
  Integrity    : VALID
  Plaintext    : hello123

test cases:
    (9, "hello 123"),
    (7, "hello123"),
    (5, "HELLO"),
    (11, "@hello!"),
    (3, ""),