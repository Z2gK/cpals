from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 12 - Byte-at-a-time ECB decryption (Simple)
# Part 4 - to solve for entire ciphertext unknown plaintext given access to
# encryption oracle as POC
# Oracle returns Enc(X || unknown, key)
# Prefix X is attacker controllable

# From previous parts we know that block size = 16 and
# plaintext length = 138 bytes

blocksize = 16 # length of each block
ptlen = 138 # known length of plaintext

# Request for 16 encryptions and store ciphertexts in cts
# The first with prefix AAAAAAAAAAAAAAA (15 'A's)
# second with prefix    AAAAAAAAAAAAAA  (14 'A's) etc
# Blocks in these ciphertexts will be needed as the target when bruteforcing
# subsequent blocks later
cts = []
fullprefix = b'A' * blocksize
for i in range(blocksize):
    prefix = fullprefix[i+1:]  # this prefix needs to keep getting shorter 
    cts.append(sc.encryptionoracle2(prefix))
# print(cts, len(cts))

fullprefix = b'A' * blocksize
solved = b'A' * blocksize
numbytes = ptlen # the number of bytes to solve for, should be <= ptlen

# loop to solve for byte 0, byte 1, etc in ciphertext block
for i in range(numbytes):
    targetctid = i % blocksize
    targetblkid = i // blocksize
    targetctblk = cts[targetctid][targetblkid * blocksize: (targetblkid+1) * blocksize]
    solvedbyte = sc.bruteforce0(solved[-15:], targetctblk, blocksize)
    solved = solved + solvedbyte

print(solved[16:])

