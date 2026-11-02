from SymmetricCrypto import MT19937 as mt
from datetime import datetime
import base64
import time

# Set 3 Challenge 24
# Generate 256-bit token from MT19937 rng, encode, and save to file
# Seed using "current time" 

#timestamp = "2026-04-01T00:00:00Z"
#dtobj = datetime.fromisoformat(timestamp)
#utime = int(dtobj.timestamp())
utime = int(time.time())
# print("Timestamp = ", timestamp)
print("Unix time = ", utime)


rng = mt(utime)
token = b''
for i in range(8):
    token = token + rng.getrand().to_bytes(4)
tokenb64 = base64.b64encode(token).decode()
print("Token:")
print(token)
print(tokenb64)

fp = open("token.txt", "w")
fp.write(tokenb64)
fp.close()
