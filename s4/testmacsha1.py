from SymmetricCrypto import MACSHA1

# Set 4 Challenge 28 - Implement a SHA-1 keyed MAC

key = b"A" * 16
mac = MACSHA1(key)
print("Key =")
print(key)

msg = 'The quick brown fox'
print("Message =")
print(msg)
print("SHA1 MAC =")
machexdigest = mac.hexdigest(msg)
print(machexdigest)

print("\nVerifying the following msg/mac")
print(msg)
print(machexdigest)
print(mac.auth(msg, machexdigest))

print("\nVerifying the following msg/mac")
msg1 = 'The crazy fox'
print(msg1)
print(machexdigest)
print(mac.auth(msg1, machexdigest))
