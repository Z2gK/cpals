from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu
from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 19 - Break fixed-nonce CTR mode using substitutions
# Part 2 - Perform basic frequency analysis

def bytesfreq(freqlist: list[int]):
    # sample input: [0, 1, 2, 0, 10, ...]
    # takes as input a list of 256 integers and produces a list of lists with
    # the following format:
    # [[f1, (b1, b2, b3)], [f2, (b4, b5)], ... ]
    # f1, f2, etc are the frequencies of occurrence
    # b1, b2, etc are the bytes with that frequencies
    uniquefreqs = set(freqlist)
    uniquefreqs.discard(0) # don't count those with zero frequency
    sortedfreqlist = []
    for x in uniquefreqs:
        s = set([i for i, item in enumerate(freqlist) if item == x])
        sortedfreqlist.append([x, s])
    sortedfreqlist.sort(key=lambda f: f[0], reverse=True)
    return sortedfreqlist

if len(sys.argv) != 2:
    print("Please filename for the CT file")
    print("Argument: <filename>")
    exit()

ctlist = []
with open(sys.argv[1], "r") as fp:
    for s in fp:
        ct = base64.b64decode(s.strip())
        ctlist.append(ct)

ciphertexts = CiphertextsCTR(ctlist)
# ciphertexts.printcts() # prettier way to print ciphertext, hex formatted
# print(ctlist)

# Collect bytes at the same positions in separate strings
# since they are xor-ed with the same key byte
# then do freq analysis on each - expect 20 length 40 strings
sameposlist = []
for i in range(ciphertexts.minctlen()):
    bytelist = [ct[i].to_bytes() for ct in ciphertexts.getcts()]
    sameposlist.append(b''.join(bytelist))

# sameposlist has 20 items, each of length 40
for idx, x in enumerate(sameposlist):
    print("Byte position =", idx)
    freqlist = cu.bytefreqs(x)
    print("Max frequency =", max(freqlist))
    print(bytesfreq(freqlist))
    print()
    # print(x, len(x))

