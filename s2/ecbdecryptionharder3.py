from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 14 - Byte-at-a-time ECB decryption (Harder)

# Part 3 - Determine the length of the unknown prefix by increasing the length
# of the attacker controlled data until the prefix block becomes constant

mybytes = b""
ct1 = sc.encryptionoracle3(mybytes)
mybytes = mybytes + b"A"
ct2 = sc.encryptionoracle3(mybytes)
blockidx = 0 # block of interest, from Part 2
blocksize = 16

while ct1[blockidx*blocksize:(blockidx+1)*blocksize] != ct2[blockidx*blocksize:(blockidx+1)*blocksize]:
    ct1 = ct2
    mybytes = mybytes + b"A"
    ct2 = sc.encryptionoracle3(mybytes)

print(f"Length of prefix inside block of interest = {16 - (len(mybytes)-1)}")
