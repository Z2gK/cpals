from CryptoUtils import CryptoUtils as cu

# Set 1 Challenge 3
# Method 2 - pick the byte with the highest frequency, guess and decrypt
# The most common byte may well match the space character
hexstring = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
ct = cu.hextobytes(hexstring)

freqlist = cu.bytefreqs(ct)
maxfreq = max(freqlist)
print(f"Maximum frequency = {maxfreq}")
maxfreqindices = [i for i, x in enumerate(freqlist) if x == maxfreq]
print("The following byte(s) in the ciphertext have maximum frequency:")
print([f"{x:02x}" for x in maxfreqindices])

# choose the top 5 plus the space character
topchars = cu.ENGLISHLETTERSORTED[:5]
topchars = topchars + topchars.lower()
topchars = topchars + " "
for x in maxfreqindices:
    # Guess it is one of the top 5 letters with highest frequencies
    # and hence the find the xor key
    # then xor this with the original string
    for c in topchars:
        xorkey = x ^ ord(c)
        xorkeyfull = xorkey.to_bytes() * len(ct)
        print(f"Guessing character {c} and trying key {xorkey:02x}")
        decrypted = cu.xor(xorkeyfull, ct)
        print(f"English text score = {cu.alphabetscore(decrypted)}")
        print(decrypted)
