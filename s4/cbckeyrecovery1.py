from SymmetricCrypto import SymmetricCrypto as sc
import os, base64

# Part 4 Challenge 27 Part 1 - Recover the key from CBC with IV=Key
def quoteout(s: str) -> str:
    s = s.replace(" ","%20").replace(";", "%3B").replace("=","%3D")
    return s

def encryptCBC(s: str, key: bytes, iv: bytes) -> bytes:
    # Takes some user controlled input string, appends and prepends certain
    # text, pads, and encrypts it
    s = quoteout(s)
    ptstr = "comment1=cooking%20MCs;userdata=" + s + ";comment2=%20like%20a%20pound%20of%20bacon"
    pt = ptstr.encode()
    pt = sc.pkcs7pad(pt)
    ct = sc.AESCBCencrypt(pt,key,iv)
    return ct

def decryptCBC(ct: bytes, key: bytes, iv: bytes) -> bytes:
    pt = sc.AESCBCdecrypt(ct,key,iv)
    pt = sc.pkcs7unpad(pt)
    # Check that characters are not high ASCII (>= 128)
    for c in pt:
        if c >= 128:
            print("Decryption failed!")
            print("High ASCII values detected!")
            print(pt)
            return pt
    print("Decryption OK")
    return pt

key = os.urandom(16)
iv = key
# output key to file for later verification
with open("key27.txt", "w") as fp: 
    fp.write(key.hex())

# The attacker can only controls userdata and send tampered ct back
# They don't know the key nor iv
x = 'A' * 16
ct = encryptCBC(x, key, iv)
c1 = ct[:16]
modct = c1 + (b'\x00' * 16) + c1 + ct[48:]
decrypted = decryptCBC(modct, key, iv)

# save decrypted PT to file pt27.txt
with open("pt27.txt", "w") as fp:
    fp.write(base64.b64encode(decrypted).decode())
print("Decrypted PT saved to pt27.txt")
