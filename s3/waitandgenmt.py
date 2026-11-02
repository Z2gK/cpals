from SymmetricCrypto import MT19937 as mt
import random, time

# Set 3 Challenge 22
# This script waits a random number of seconds between 40-1000s
# THen generate a random number from the MT19937 rng using Unix time as seed
# Wait a random number of seconds again
# Output ONE 32-bit output of the rng
# Also output seed value to file seed.txt

before = random.randint(40, 1001)
after =  random.randint(40, 1001)
#before = random.randint(5, 11)
#after =  random.randint(5, 11)

time.sleep(before)
seed = int(time.time())
rng = mt(seed)
fp = open("seed.txt", "w")
fp.write(str(seed))
fp.close()
time.sleep(after)
x = rng.getrand()
print("RNG output = ", x)
