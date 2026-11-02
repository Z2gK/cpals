from SymmetricCrypto import MT19937 as mt
# from datetime import datetime
import time
import base64

# Set 3 Challenge 24
# bruteforce and find seed (unix time) that generated token

fp = open("token.txt", "r")
tokenb64 = fp.read()
fp.close()

token = base64.b64decode(tokenb64)
currutime = int(time.time())
endutime = currutime - 60*60*24*365 # limit search to 1 year back

t = currutime
while t > endutime:
    rng = mt(t)
    token_ = b''
    for i in range(8):
        token_ = token_ + rng.getrand().to_bytes(4)
    if token_ == token:
        print("Seed found")
        print(t)
        break
    t = t - 1
