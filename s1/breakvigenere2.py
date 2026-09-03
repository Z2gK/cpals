from CryptoUtils import CryptoUtils as cu
import sys, base64

# Set 1 Challenge 6

# Part 3 : Find repeating key
if len(sys.argv) != 3:
    print("Break repeating key xor given ciphertext and keysize")
    print("Arguments: <filename (b64-encoded file)> <keysize>")
    exit()

fname = sys.argv[1]
keysize = int(sys.argv[2])
with open(fname, "r") as fp:
    b64text = fp.read()
ct = base64.b64decode(b64text)
splitctlist = cu.vigeneresplit(ct, keysize)

key = b''
for index, splitct in enumerate(splitctlist, start=0):
    print(f"Position = {index}")
    candidates = cu.trysinglebytexor(splitct, 0.85)
    print(candidates)
    if len(candidates) == 1:
        key = key + candidates[0][1].to_bytes()
    else:
        key = key + b'\00'

print(key)

#    freqscorelist = [0]*256
#    xoredlist = []
#    maxalphabetscore = 0.0
#    pt = None
