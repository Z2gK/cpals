from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 12 - Byte-at-a-time ECB decryption (Simple)

# Part 1 - find out the block size of the cipher
# The idea is to increase the size of the attacker controlled prepended pt
# and see when the block size increases
mybytes = b""
ct = sc.encryptionoracle2(mybytes)
print("Ciphertext:")
print(ct)
origlen = len(ct)
print(f"Original ciphertext length = {origlen}")
ctlen = origlen
while ctlen == origlen:
    mybytes = mybytes + b'A'
    ct = sc.encryptionoracle2(mybytes)
    ctlen = len(ct)
print(f"CT length extended = {ctlen}")
print(f"Blocksize = {ctlen-origlen}")
print(f"Length of prepended plaintext = {len(mybytes)}")
