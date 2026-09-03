from CryptoUtils import CryptoUtils as cu
import sys, base64

# Set 1 Challenge 6

# Part 3 : Decrypt b64 encoded text (vigenere encrypted) given key
if len(sys.argv) != 2:
    print("Decrypt encrypted text")
    print("Arguments: <filename (b64-encoded file)>")
    exit()

fname = sys.argv[1]
with open(fname, "r") as fp:
    b64text = fp.read()
ct = base64.b64decode(b64text)

key = b'Terminator X: Bring the noise'
pt = cu.vigenere(ct, key)
print("Key:")
print(key)
print("\nDecrypted text:")
print(pt.decode())
