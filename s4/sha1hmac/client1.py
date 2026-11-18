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

filename = "brownfox.txt"
IP = "127.0.0.1"
port = 8080
baseurl = "http://" + IP + ":" + str(port) + "/test?file=" + filename + "&hmac="

# 20 byte sha1 hmac
# h = b"\x4a" + b"\x00" * 19
h = b'\x00' * 20

# set of bytes to vary target byte in hash over
b = os.urandom(10)
hashes = genhashset(h, b, 0)
# known hash of file = 4ab0dc824b0ed6cc4cf1a30d1274b8cf0bd0720a
hashes.append(b'\x4a' + b'\x00' * 19)  # add correct hash to see timing difference

for x in hashes:
    url = baseurl + x.hex()
    print(x.hex())
    start = time.time()
    response = requests.get(url)
    end = time.time()
    status_code = response.status_code
    print(status_code, end - start)


