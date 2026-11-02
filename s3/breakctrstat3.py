# from SymmetricCrypto import SymmetricCrypto as sc
# from CryptoUtils import CryptoUtils as cu
from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 20
# Part 3: Assemble ciphertext bytes in the same column from col 53 onwards
# and decide which ones are long enough for decryption

if len(sys.argv) != 2:
    print("Please enter filename for the CT file")
    print("Argument: <filename>")
    exit()

ctlist = []
with open(sys.argv[1], "r") as fp:
    for s in fp:
        ct = base64.b64decode(s.strip())
        ctlist.append(ct)

# Determine the columns that have sufficient bytes which we want to try
# and decrypt
ciphertexts = CiphertextsCTR(ctlist)
ctlengths = ciphertexts.numbytesincols
print(ctlengths)

# Find position of item
item = 22
print(f"Item {item} is at position {ctlengths.index(22)} in list")

