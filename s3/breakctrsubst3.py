from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu
from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 19 - Break fixed-nonce CTR mode using substitutions
# Part 3 - print the ciphertext in nice hex encoded format

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
ciphertexts.printcts()
