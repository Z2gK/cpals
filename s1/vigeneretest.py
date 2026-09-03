from CryptoUtils import CryptoUtils as cu

# Set 1 Challenge 5
# Encrypts a given string using the Vigenere cipher

ptstring = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
pt = ptstring.encode()
key = b'ICE'

ct = cu.vigenere(pt, key)
print(cu.bytestohex(ct))
