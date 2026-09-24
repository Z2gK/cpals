from SymmetricCrypto import SymmetricCrypto as sc

# Part 2 Challenge 16 - CBC bitflipping attacks

def quoteout(s: str) -> str:
    s = s.replace(" ","%20").replace(";", "%3B").replace("=","%3D")
    return s

def encryptCBC(s: str) -> bytes:
    # Takes some user controlled input string, appends and prepends certain
    # text, pads, and encrypts it
    # TODO: function should quote out ; and = characters
    s = quoteout(s)
    ptstr = "comment1=cooking%20MCs;userdata=" + s + ";comment2=%20like%20a%20pound%20of%20bacon"
    pt = ptstr.encode()
    key = b"YELLOW SUBMARINE"
    pt = sc.pkcs7pad(pt)
    iv = b'0123456789abcdef'
    ct = sc.AESCBCencrypt(pt,key,iv)
    return ct

def decryptCBC(ct: bytes) -> bytes:
    key = b"YELLOW SUBMARINE"
    iv = b'0123456789abcdef'
    pt = sc.AESCBCdecrypt(ct,key,iv)
    pt = sc.pkcs7unpad(pt)
    print(pt)
    return pt

def decryptndetect(ct: bytes) -> bool:
    pt = decryptCBC(ct)
    isAdmin = False
    if b";user=admin;" in pt:
        isAdmin = True
    return isAdmin

def bitflip(ct: bytes) -> bytes:
    # A very specific function that targets block 2 CT to change last 11 bytes
    # of block 3 PT to ;user=admin
    s = ";user=admin"
    slen = len(s)
    ctpart = b""
    userbyteval = ord("A") # known PT byte value at position to be corrupted
    for id, c in enumerate(s):
        x = ord(c) ^ userbyteval ^ ct[2*16+(16-slen)+id]
        ctpart = ctpart + x.to_bytes()
    ct = ct[:2*16+ (16-slen)] + ctpart + ct[3*16:]
    return ct

# TODO: write another function that checks for the target string in the
# decrypted data

s1 = "comment1=cooking%20MCs;userdata="
s2 = ";comment2=%20like%20a%20pound%20of%20bacon"
#print(len(s1))
#print(len(s2))

# userdata = "this is my test string;user=admin"
userdata = "A" * 32
ct = encryptCBC(userdata)
#print(ct)

# TODO: PERFORM CBC BIT FLIP
# Manipulate ciphertext block 2 to change last 12 bytes of plaintext block 3
ctnew = bitflip(ct)
print(ctnew)

# print(ct)
#pt = decryptCBC(ct)
#print(pt)

isAdmin = decryptndetect(ctnew)
print("User is admin:")
print(isAdmin)
