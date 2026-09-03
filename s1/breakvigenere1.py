from CryptoUtils import CryptoUtils as cu
import sys, base64
import matplotlib.pyplot as plt
import numpy as np

# Set 1 Challenge 6

# Part 1: Testing the hamming distance function
# We expect 37 for the hamming distance
s1 = "this is a test"
s2 = "wokka wokka!!!"

s12dist = cu.hamming(s1.encode(), s2.encode())
print(s1)
print(s2)
print(f"Hamming distance = {s12dist}")


# Part 2: Finding the key size
fname = "6.txt"
with open(fname, "r") as fp:
    b64text = fp.read()
# print(b64text)

ct = base64.b64decode(b64text)
# print(ct)
print(f"Length of ciphertext = {len(ct)}")
# ct = ct[100:]
numblocks = 8 # needs to be an even number
rangelist = list(range(2,41))
normscores = []
for keysize in rangelist:
    hammingdistances = []
    for i in range(numblocks // 2):
        block1 = ct[2*i*keysize:(2*i+1)*keysize]
        block2 = ct[(2*i+1)*keysize:(2*i+2)*keysize]
        hamming = cu.hamming(block1,block2)
        hammingdistances.append(hamming)
    normscore = sum(hammingdistances)/(1.0*len(hammingdistances)*keysize)
    normscores.append(normscore)
    print(f"Keysize = {keysize}; Score = {normscore}")

plt.bar(rangelist, normscores)
plt.xlabel("Keysize")
plt.ylabel("Score")
plt.title(f"Number of blocks = {numblocks}")
plt.savefig("scores.png")
plt.show()

    
