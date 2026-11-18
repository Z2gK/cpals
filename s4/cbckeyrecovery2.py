from SymmetricCrypto import SymmetricCrypto as sc
import base64

# Part 4 Challenge 27 Part 2 - Recover the key from CBC with IV=Key
print("Reading PT from pt27.txt")
with open("pt27.txt", "r") as fp:
    s = fp.read()
    PT = base64.b64decode(s)

k = sc.xor(PT[:16], PT[32:48])
print("Recovered key:")
print(k.hex())
