from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu
from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 20
# Part 2: Assemble long ciphertext from CTR mode encrypted CTs and break
# using method developed for Vignere cipher

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

# Assemble long CT string consisting of only the first 53 bytes of each string
blocklen = 53
ct = b""
for c in ctlist:
    ct = ct + c[:blocklen]

print(len(ct))

# Run the Vignere breaking function - do this only for the first 53 bytes
splitctlist = cu.vigeneresplit(ct, blocklen)

# key = b''
keylist = []
for index, splitct in enumerate(splitctlist, start=0):
    print(f"Position = {index}")
    candidates = cu.trysinglebytexor(splitct, 0.85)
    candidates.sort(key=lambda item: item[0], reverse=True) # take the byte with highest score later
    print(candidates)
    if len(candidates) != 0:
        #key = key + candidates[0][1].to_bytes()
        keylist.append(candidates[0][1].to_bytes())
    else:
        #key = key + b'\00'
        keylist.append(b"")

# Pass the guessed keystream bytes to trykeys() function of the CiphertextCTR
# instance and let it try to decrypt and print
# 
#print(key)
# print(keylist, len(keylist))
guessbytes = [(pos,b) for pos, b in enumerate(keylist)]
# remove any empty key bytes, if any
guessbytes = [(item[0], item[1]) for item in guessbytes if item[1] != b'']

guessbytes[0] = (0, (124).to_bytes()) # manual intervention here as this keystream byte produces UPPERCASE letters for the beginning of the sentence
print("List of (position, keystream byte):")
print(guessbytes)

ciphertexts.trykeys(guessbytes)
ciphertexts.printguessbrief()

