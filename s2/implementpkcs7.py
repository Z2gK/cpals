from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 9 - Implement PKCS#7 padding

pt = b"YELLOW SUBMARINE"
ptpadded = sc.pkcs7pad(pt)
print("Plaintext:")
print(pt)
print("Padded plaintext (assuming 16-byte blocksize by default):")
print(ptpadded)
print("===")

ptpadded20 = sc.pkcs7pad(pt,20)
print("Plaintext:")
print(pt)
print("Padded plaintext (blocksize = 20) :")
print(ptpadded20)

