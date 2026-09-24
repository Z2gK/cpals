from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 14 - Byte-at-a-time ECB decryption (Harder)
# Part 4 - to solve for entire ciphertext unknown plaintext given access to
# encryption oracle as POC
# Oracle returns Enc(unknown prefix || X || unknown, key)
# String X is attacker controllable

# From previous parts we know that block size = 16
# unknown prefix length in last prefix block = 12
# plaintext length = 138 bytes
# attackerblkid is the id of the first block fully controllable by attacker
# last prefix block id = 0

blocksize = 16 # length of each block
ptlen = 138 # known length of plaintext
unkprefixlen = 12 # length of the unknown prefix in its last block
unkprefixpadlen = blocksize - unkprefixlen   # 4
attackerblkid = 1

# Request for 16 encryptions and store ciphertexts in cts
# The first with prefix AAAAAAAAAAAAAAA (15 'A's)
# second with prefix    AAAAAAAAAAAAAA  (14 'A's) etc
# Blocks in these ciphertexts will be needed as the target when bruteforcing
# subsequent blocks later
cts = []
partialprefix = b'A' * blocksize
unkprefixpad = b'A' * unkprefixpadlen

for i in range(blocksize):
    myprefix = partialprefix[i+1:]  # this prefix needs to keep getting shorter 
    cts.append(sc.encryptionoracle3(unkprefixpad + myprefix))

# Remove blocks from ct so that we can use code previously written
cts2 = []
for ct in cts:
    cts2.append(ct[attackerblkid*blocksize:])

solved = b'A' * blocksize
numbytes = ptlen # the number of bytes to solve for, should be <= ptlen

# loop to solve for byte 0, byte 1, etc in ciphertext block
# we need to use a new function bruteforce1
for i in range(numbytes):
    targetctid = i % blocksize
    targetblkid = i // blocksize
    targetctblk = cts2[targetctid][targetblkid * blocksize: (targetblkid+1) * blocksize]
    solvedbyte = sc.bruteforce1(unkprefixpad, solved, targetctblk, attackerblkid, blocksize)
    solved = solved + solvedbyte

print(solved[blocksize:])
