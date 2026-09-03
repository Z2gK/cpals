from CryptoUtils import CryptoUtils as cu
import sys


if len(sys.argv) != 2:
    print("Detect single byte XOR given hex encoded strings")
    print("Argument: <filename>")
    sys.exit()

hexstringlist = []
with open(sys.argv[1], "r") as fp:
    for line in fp:
        hexstringlist.append(line.strip())

# print(hexstringlist)
for hexstring in hexstringlist:
    print(hexstring)
    ct = cu.hextobytes(hexstring)
    candidates = cu.trysinglebytexor(ct)
    for candidate in candidates:
        print(f"Single byte XOR = {f"0x{candidate[1]:02x}"}, score = {candidate[0]}")
        print(candidate[2])
