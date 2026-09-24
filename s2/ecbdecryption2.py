from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu

# Set 2 Challenge 12 - Byte-at-a-time ECB decryption (Simple)

# Part 2 - to confirm and mode used by oracle is ECB
# Uses code from Challenge 11 detectecbcbc.py

mybytes = b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
ct = sc.encryptionoracle2(mybytes)
print("Ciphertext:")
print(ct)
repeatedblocks = cu.detectrepeatedblocks(ct)

if repeatedblocks:
    print("Encryption is in ECB mode. Repeated block(s):")
    print(repeatedblocks)

