from SymmetricCrypto import SymmetricCrypto as sc
import base64, os, sys

# Set 3 Challenge 19 - Break fixed-nonce CTR mode using substitutions
# Part 1 - Encrypt all PT strings using AES CTR with the same key and nonce
# and output to file

key = os.urandom(16)  # 128 bit AES key
nonce = b'\x00' * 16

if len(sys.argv) != 3:
    print("Please provide input and output filenames")
    print("Argument: <input filename> <output filename>")
    exit()

ctlist = []

with open(sys.argv[1], "r") as fp:
    for s in fp:
        pt = base64.b64decode(s.strip())
        ct = sc.AESCTRencrypt(pt, key, nonce)
        ctlist.append(ct)

#print("list of CT:")
#print(ctlist)
print("Number of CTs = ")
print(len(ctlist))
print("Lengths of each CT:")
lengths = [len(c) for c in ctlist]
print(lengths)
print("Min/max CT lengths = ", min(lengths), max(lengths))

with open(sys.argv[2], "w") as ofp:
    for c in ctlist:
        ofp.write(base64.b64encode(c).decode('utf-8') + "\n")

