import requests, time, os

# Set 4 Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak

def genhashset(orig: bytes, byteset: bytes, targetidx: int):
    # generate a list of candidate hashes for use in timing attack brute force
    # assume that orig is 20 bytes and 0 <= targetidx < 19
    # no error checking here
    hashset = []
    for b in byteset:
        hashset.append(orig[:targetidx] + b.to_bytes() + orig[targetidx+1:])
    return hashset

def stats(times):
    n = int(len(times) * 0.8)
    times.sort()
    sample = times[:n]
    m = len(sample)
    mean = sum(sample)/m
    sample2 = [x*x for x in sample]
    std = (sum(sample2)/m - mean**2) ** 0.5
    return mean, std

filename = "brownfox.txt"
IP = "127.0.0.1"
port = 8080
baseurl = "http://" + IP + ":" + str(port) + "/test?file=" + filename + "&hmac="

# 20 byte sha1 hmac
# h = b"\x4a" + b"\x00" * 19
solved = b'\x00' * 20

nbytes = 20 # solve for the first nbytes bytes of the hash
# nvar = 20
allbytes = b''.join([x.to_bytes() for x in range(256)])

known = "4ab0dc824b0ed6cc4cf1a30d1274b8cf0bd0720a"
for i in range(nbytes):
    # do the actual brute forcing
    hashset = genhashset(solved, allbytes, i)
    max = 0.0
    timings = []
    for x in hashset:
        url = baseurl + x.hex()
        # print(x.hex())
        start = time.time()
        response = requests.get(url)
        end = time.time()
        status_code = response.status_code
        timing = end - start
        timings.append(timing)
        if timing > max:
            max = timing
            solved = x
    # print(timings)
    print(solved.hex())
    if solved[:i+1].hex() != known[:(i+1)*2]:
        print("HMAC incorrect!")
        exit()
    
# Compare with known hash
known = "4ab0dc824b0ed6cc4cf1a30d1274b8cf0bd0720a"
if solved.hex() == known:
    print("HMAC matches!")
else:
    print("HMAC incorrect!")
