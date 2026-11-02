from SymmetricCrypto import SymmetricCrypto as sc
import base64 

# Set 3 Challenge 18 - Implement CTR, the stream cipher mode
# Implements AES CTR mode and tests decryption of given string

ctb64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="  # given string
ct = base64.b64decode(ctb64)
key = b"YELLOW SUBMARINE"
nonce = b"\x00" * 16
pt = sc.AESCTRdecrypt(ct, key, nonce)
print(pt)

