from SymmetricCrypto import SymmetricCrypto as sc
from CryptoUtils import CryptoUtils as cu
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

keylist = []
startcol = 53
endcol = 96
for col in range(startcol, endcol+1):
    print(f"Position = {col}")
    candidates = cu.trysinglebytexor(ciphertexts.getcol(col), 0.85)
    candidates.sort(key=lambda item: item[0], reverse=True) # take the byte with highest score later
    print(candidates)
    if len(candidates) != 0:
        #key = key + candidates[0][1].to_bytes()
        keylist.append(candidates[0][1].to_bytes())
    else:
        #key = key + b'\00'
        keylist.append(b"")

guessbytes2 = [(pos,b) for pos, b in enumerate(keylist, start=startcol)]
# print(guessbytes2)

# for columns 0 to 52
guessbytes1 = [(0, b'|'), (1, b'\xe7'), (2, b']'), (3, b'\x19'), (4, b'\x95'), (5, b'\x8a'), (6, b'\x90'), (7, b't'), (8, b'\x83'), (9, b'`'), (10, b'8'), (11, b'\xb9'), (12, b'\xb5'), (13, b'I'), (14, b'\xf3'), (15, b'\x89'), (16, b'\x01'), (17, b'4'), (18, b'\x16'), (19, b'\x93'), (20, b'\xce'), (21, b'u'), (22, b'W'), (23, b'\xbc'), (24, b'l'), (25, b'S'), (26, b'\xf5'), (27, b'\x06'), (28, b'.'), (29, b'S'), (30, b'\xaf'), (31, b'`'), (32, b'\x9e'), (33, b'\xd1'), (34, b'\xfc'), (35, b'\xe5'), (36, b'\x7f'), (37, b'@'), (38, b'\x19'), (39, b'\xa8'), (40, b'`'), (41, b'm'), (42, b'\xe7'), (43, b'\x86'), (44, b'\xbf'), (45, b'\xa5'), (46, b'b'), (47, b'}'), (48, b'\x0f'), (49, b'\xfa'), (50, b'\xdc'), (51, b':'), (52, b'\x10')]

guessbytes = guessbytes1 + guessbytes2
# remove the empty key bytes, if any
guessbytes = [(item[0], item[1]) for item in guessbytes if item[1] != b'']

print("List of (position, keystream byte):")
print(guessbytes)
ciphertexts.trykeys(guessbytes)



ciphertexts.printguessbrief()
