from Crypto.Cipher import AES
import sys, base64

# Set 1 Challenge 7

# Read a file containing b64 encoded ciphertext and decrypts it using a
# given key
if len(sys.argv) != 2:
    print("Decrypt text encrypt with AES-ECB")
    print("Arguments: <filename (b64-encoded file)>")
    exit()

fname = sys.argv[1]
with open(fname, "r") as fp:
    b64text = fp.read()
ct = base64.b64decode(b64text)
key = b"YELLOW SUBMARINE"

cipher = AES.new(key, AES.MODE_ECB)
pt = cipher.decrypt(ct)
print(pt) # print bytes
# print(pt.decode()) # print as a string
