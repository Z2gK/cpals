from SymmetricCrypto import SymmetricCrypto as sc

prefix = b"abcdefgkjshf..."
ct = sc.encryptionoracle2(prefix)
print(ct)

key = b'yellow submarine'
decrypted = sc.AESECBdecrypt(ct, key)
print(decrypted)
