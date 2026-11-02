from SymmetricCrypto import MT19937 as mt
import base64

# Set 3 Challenge 24
# encrypt chosen string, encode ct and save to file

key = 0xabcd # 16 bit key for seed
rng = mt(key)

ptlen = 20  # attacker specified
pt = b'A' * ptlen # attacker specified
ct = rng.encrypt(pt)  # ct will be longer than pt because of prefix

print("Length of pt = ", len(pt))
print("Length of ct = ", len(ct))
print("CT:")
print(ct)

ctb64 = base64.b64encode(ct).decode()
print(ctb64)

fp = open("ct24.txt", "w")
fp.write(ctb64)
fp.close()

