from CryptoUtils import CryptoUtils as cu

divider = "\n========================\n"

# Set 1 Challenge 1
hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print("Set 1, Challenge 1 - Convert hex to base64")
print("Original hex-encoded string:")
print(hexstring)
print("Base-64 encoded:")
print(cu.hextob64(hexstring))
print(divider)

h1 = "1c0111001f010100061a024b53535009181c"
h2 = "686974207468652062756c6c277320657965"
print("Set 1, Challenge 2 - Fixed XOR")
print("Original hex-encoded strings:")
print(h1)
print(h2)
print("Result after XORing:")
print(cu.xorhex(h1, h2))
print(divider)

