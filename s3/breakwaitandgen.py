from SymmetricCrypto import MT19937 as mt
from datetime import datetime
import sys

# Set 3 Challenge 22
# Arguments: <time in ISO8601 format> <rng output in decimal>
# run date -Is to generate timestamp
# Tries to obtain the seed of the rng

# sample ISO8601 conversion
# iso_string = "2026-10-20T15:30:45.123456Z"
# dt_obj = datetime.fromisoformat(iso_string)
# unixtimestamp = dt_obj.timestamp()
if len(sys.argv) != 3:
    print("Arguments: <time in ISO8601 format, date -Is> <rng output in decimal>")
    exit()

iso = sys.argv[1]
dtobj = datetime.fromisoformat(iso)
unixtime = int(dtobj.timestamp())
x = int(sys.argv[2])

# Brute force seed by trying the last few thousand seconds
numsec = 3600 # 1 hr
for t in range(unixtime, unixtime-numsec, -1):
    rng = mt(t)
    if rng.getrand() == x:
        print("Seed found: ", t)
        exit()

print("Seed not found")

