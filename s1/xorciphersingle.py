from CryptoUtils import CryptoUtils as cu

# Set 1 Challenge 3
# Method 1 - try all 256 possibilities and look at letter frequencies
hexstring = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
ct = cu.hextobytes(hexstring)
freqscorelist = [0]*256 # keeps track of the score for each pt candidate
xoredlist = [] # stores the xored string

for x in range(256):
    xorstring = x.to_bytes() * len(ct)
    decrypted = cu.xor(ct, xorstring)
    xoredlist.append(decrypted)
    freqlist = cu.englishletterfreqs(decrypted) 
    freqscore = sum(freqlist[:10]) # We take only top 10 and sum their freqs
    freqscorelist[x] = freqscore # and this is the score

# lists scores in descending order (dedup, conv to list, sort)
# e.g. [17, 16, 15, 14, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 1, 0]
highscorelist = sorted(list(set(freqscorelist)), reverse=True)

# print the plaintext for xor bytes with top 4 scores
for s in highscorelist[:4]:
    for x in range(256):
        if freqscorelist[x] == s:
            print(xoredlist[x])
            # print(f"byte = {x}, score = {s}")
            print(f"byte = {x:02x}")
            print(f"Most frequent letters score = {s}")
            # ptbytes = bytes.fromhex(xoredlist[x])
            print(f"English alphabet score = {cu.alphabetscore(xoredlist[x])}")
            print("===")
