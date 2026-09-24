from SymmetricCrypto import SymmetricCrypto as sc

s1 = b"ICE ICE BABY\x05\x05\x05\x05"
s2 = b"ICE ICE BABY\x01\x02\x03\x04"

try:
    print("Padded string:")
    print(s1)
    print("Unpadded string:")
    print(sc.pkcs7unpad(s1))
except:
    print("Bad padding!")

print("===")

try:
    print("Padded string:")
    print(s2)
    print("Unpadded string:")
    print(sc.pkcs7unpad(s2))
except:
    print("Bad padding!")
