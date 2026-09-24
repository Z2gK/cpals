from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu

# Set 2 Challenge 11 - An ECB/CBC detection oracle
# Send "attacker-controlled" plaintext to oracle function encryptionoracle1()
# which encrypts in ECB or CBC half the time

# plaintext chosen so that at least two blocks will fall within this
# repeating pattern and generate repeated ciphertext blocks in ECB mode
pt =   b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
ct = sc.encryptionoracle1(pt)
print("Ciphertext:")
print(ct)
repeatedblocks = cu.detectrepeatedblocks(ct)

if repeatedblocks:
    print("Encryption is in ECB mode. Repeated block(s):")
    print(repeatedblocks)
else:
    print("Encryption is in CBC mode")

