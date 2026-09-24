# from Crypto.Cipher import AES
from SymmetricCrypto import SymmetricCrypto as sc
import sys, base64


# Set 2 Challenge 10 - Implement CBC mode

if len(sys.argv) != 2:
    print("Decrypt text encrypt with AES-CBC")
    print("Arguments: <filename (b64-encoded file)>")
    exit()

fname = sys.argv[1]
with open(fname, "r") as fp:
    b64text = fp.read()
ct = base64.b64decode(b64text)
key = b"YELLOW SUBMARINE"
iv = b"\x00" * 16
pt = sc.AESCBCdecrypt(ct, key, iv)
print(pt)


# Test code for AES CBC encryption and decryption
#pt = b"This is some plaintext. The quick brown fox jumps over the lazy dog"
#print(len(pt))
#pt = sc.pkcs7pad(pt)
#print(len(pt))

#key = b"YELLOW SUBMARINE"
#ct = sc.AESECBencrypt(pt, key)
#print(ct)
#print(len(ct))

#key = b"YELLOW SUBMARINE"
#iv = b"\x00" * 16
#ct = sc.AESCBCencrypt(pt, key, iv)
#print(ct)
#print(len(ct))

#decrypted = sc.AESCBCdecrypt(ct, key, iv)
#print(decrypted)
#print(len(decrypted))
