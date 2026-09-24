from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu

# Set 2 Challenge 14 - Byte-at-a-time ECB decryption (Harder)

# Part 2 - Find out which block contain the prepended unknown prefix
# Since this is ECB, the idea is to introduce attacker controlled repeated
# blocks and see where they lie
# We know from Part 1 that the blocksize is 16

mybytes = b""
ct = sc.encryptionoracle3(mybytes)
print("Ciphertext without attacker bytes:")
print(ct)
cu.detectrepeatedblocks(ct) # confirm that there are no repeated blocks

mybytes = b"AAAAAAAAAAAAAAAA" * 3 # this will produce 2  repeated blocks
ct = sc.encryptionoracle3(mybytes)
print("Ciphertext with 3 blocks of As in attacker bytes:")
print(ct)
repeatedblocks = cu.detectrepeatedblocks(ct)
print("Repeated block(s):")
print(repeatedblocks)
print("Byte position of repeated block:")
for b in repeatedblocks:
    pos = ct.find(b)
    print(pos)
