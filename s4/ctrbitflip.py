from SymmetricCrypto import SymmetricCrypto as sc
import os

# Part 4 Challenge 26 - CTR bitflipping
# Some code taken from Part 2 Challenge 16

def quoteout(s: str) -> str:
    s = s.replace(" ","%20").replace(";", "%3B").replace("=","%3D")
    return s

def encryptCTR(s: str, key: bytes, nonce: bytes) -> bytes:
    ptstr = "comment1=cooking%20MCs;userdata=" + s + ";comment2=%20like%20a%20pound%20of%20bacon"
    pt = ptstr.encode()
    return sc.AESCTRencrypt(pt, key, nonce)

def decryptCTR(ct: str, key: bytes, nonce: bytes) -> bytes:
    return sc.AESCTRdecrypt(ct, key, nonce)
    pass


def decryptndetect(ct: bytes, key, nonce) -> bool:
    pt = decryptCTR(ct, key, nonce)
    isAdmin = False
    if b";user=admin;" in pt:
        isAdmin = True
    return isAdmin

def ctrbitflip(ct: bytes) -> bytes:
    # modify block 2
    # ;user=admin has 11 bytes
    x = ct[37:48]
    p = b"A" * 11
    ks = sc.xor(x, p)
    t = ";user=admin"
    x_ = sc.xor(ks, t.encode())
    ctnew = ct[:37] + x_ + ct[48:]
    return ctnew

s1 = "comment1=cooking%20MCs;userdata="
s2 = ";comment2=%20like%20a%20pound%20of%20bacon"

key = os.urandom(16)
nonce = b'\x00' * 16

# The attacker can only controls userdata and send tampered ct back
# They don't know the key nor nonce
userdata = "A" * 16
ct = encryptCTR(userdata, key, nonce)
ctnew = ctrbitflip(ct)

isAdmin = decryptndetect(ctnew, key, nonce)
print("User is admin:")
print(isAdmin)


