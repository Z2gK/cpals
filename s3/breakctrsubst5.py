from SymmetricCrypto import SymmetricCrypto as sc
from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 19 - Break fixed-nonce CTR mode using substitutions
# Part 5 - Investigate trigrams and tetragrams


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

# Filter out interesting trigrams
trigramdictfreq = {}
for ct in ciphertexts.getcts():
    for i in range(len(ct)-3+1):
        if ct[i:i+3] in trigramdictfreq:
            trigramdictfreq[ct[i:i+3]] = trigramdictfreq[ct[i:i+3]] + 1
        else:
            trigramdictfreq[ct[i:i+3]] = 1

print("Total number of trigrams =", len(trigramdictfreq))
trigramfiltered = {}
for k,v in trigramdictfreq.items():
    if v > 2:
        trigramfiltered[k] = v
print("Number of trigrams with freq > 2 =", len(trigramfiltered))
print(trigramfiltered)

# Filter out interesting tetragrams
tetragramdictfreq = {}
for ct in ciphertexts.getcts():
    for i in range(len(ct)-4+1):
        if ct[i:i+4] in tetragramdictfreq:
            tetragramdictfreq[ct[i:i+4]] = tetragramdictfreq[ct[i:i+4]] + 1
        else:
            tetragramdictfreq[ct[i:i+4]] = 1
print("Total number of tetragrams =", len(tetragramdictfreq))
tetragramfiltered = {}
for k,v in tetragramdictfreq.items():
    if v > 2:
        tetragramfiltered[k] = v
print("Number of tetragrams with freq > 2 =", len(tetragramfiltered))
print(tetragramfiltered)

# Sort and find positions
# print("Trigrams")
for k, v in trigramfiltered.items():
    print("Trigram =", sc.bytestohex(k), "; Freq =", v)
    for idx, ct in enumerate(ciphertexts.getcts()):
        pos = ct.find(k)
        if pos >= 0:
            print("At CT", idx, ", position =", pos)

for k, v in tetragramfiltered.items():
    print("Tetragram =", sc.bytestohex(k), "; Freq =", v)
    for idx, ct in enumerate(ciphertexts.getcts()):
        pos = ct.find(k)
        if pos >= 0:
            print("At CT", idx, ", position =", pos)

