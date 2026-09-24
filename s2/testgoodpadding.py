from SymmetricCrypto import SymmetricCrypto as sc

s1 = b"ICE ICE BABY\x04\x04\x04\x04"
s2 = b"The quick brown fox jumps\x07\x07\x07\x07\x07\x07\x07"

print("Padded string:")
print(s1)
print("Unpadded string:")
print(sc.pkcs7unpad(s1))

print("===")

print("Original string:")
print(s2)
print("Unpadded string:")
print(sc.pkcs7unpad(s2))
