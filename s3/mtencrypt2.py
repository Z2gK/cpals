from SymmetricCrypto import MT19937 as mt
from SymmetricCrypto import SymmetricCrypto as sc
import base64

# Set 3 Challenge 24
# try to find 16-bit seed (key) from ct


fp = open("ct24.txt", "r")
ctb64 = fp.read()
# print(ctb64)

ptlen = 20
ct = base64.b64decode(ctb64)
ctlen = len(ct)
print("Length of CT = ", ctlen)
print(ct)

prefixlen = ctlen - ptlen
prefix = b"X" * prefixlen
pt = prefix + (b"A" * ptlen)

# bruteforce 16-bit key/seed
for key in range(0x10000):
    rng = mt(key)
    keystream = b''
    for i in range(ctlen):
        keystream = keystream + (rng.getrand() & 0xff).to_bytes()
    ct_ = sc.xor(keystream, pt)
    if ct_[-ptlen:] in ct:
        print("Seed found!")
        print(hex(key))
        break
