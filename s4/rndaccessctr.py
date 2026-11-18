from SymmetricCrypto import SymmetricCrypto as sc
from SymmetricCrypto import RndAccessCTR
import sys, os

# Set 4 Challenge 25
# Break random access read/write CTR mode

# Use the recovered plaintext from Set 1 Challenge 7
if len(sys.argv) != 2:
    print("Please provide filename to be encrypted")
    print("Argument: <input filename>")
    exit()

fp = open(sys.argv[1], "r")
pt = fp.read()
pt = pt.encode()
fp.close()

# key = b'\xaa' * 16
key = os.urandom(16)
nonce = b'\x00' * 16
rndaccessct = RndAccessCTR(pt, key, nonce)

#pt = b'The quick brown fox'
#rndaccessct = RndAccessCTR(pt, key, nonce)
#rndaccessct.printct()
#rndaccessct.printcthex()
#ct = rndaccessct.getct()
#print("length of PT = ", len(pt))
#print("length of CT = ", len(ct))
#rndaccessct.edit(4, b'crazy')
#rndaccessct.printcthex()

# From here on we the attacker can only access the CT and edit function
ct = rndaccessct.getct()
ctlen = len(ct)
print("Length of CT =", ctlen)

# To uncover the keystream, we just have to substitute the entire string
# with some known plaintext and then check the ciphertext again
newtext = b'A' * ctlen
rndaccessct.edit(0, newtext)
newct = rndaccessct.getct()
newctlen = len(newct)
print("Length of new CT =", newctlen)

keystream = sc.xor(newtext, newct)
decrypted = sc.xor(keystream, ct)
print(decrypted)
