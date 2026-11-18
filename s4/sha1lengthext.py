from SymmetricCrypto import MACSHA1

# Set 4 Challenge 29 - Break a SHA-1 keyed MAC using length extension

def padding(msg) -> bytes:
    # return SHA1 padding for a message as bytes

    # convert msg to bytes
    if (type(msg) != str) and (type(msg) != bytes):
        print("Message should be a text or byte string!")
        raise TypeError
    if type(msg) == str:
        msg = msg.encode()

    ml = len(msg) * 8
    padding = b"\x80"
    padding += b"\x00" * (-(len(msg+padding) + 8) % 64)
    # padding += struct.pack(">Q", ml)
    padding += ml.to_bytes(8, byteorder='big')
    return padding

# Testing the padding generation function
print("Testing padding generation function")
msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
p = padding(msg)
print("Message =", msg)
print("Padding =", p)


# Let's assume the MAC key is 16 bytes in length
# Generate MAC of original message
key = b"A" * 16
mac1 = MACSHA1(key)
hash1 = mac1.digest(msg)
padding1 = padding(key+msg)

print("\nGenerating MAC of original message")
print("MAC = ", hash1)
print(mac1.hexdigest(msg))
print("Padding = ", padding1)
print("Lengths of key, msg, padding =", len(key), len(msg), len(padding1))
origlen = len(key) + len(msg) + len(padding1)

# Compute the correct MAC of the tampered msg without length extension
admintxt = b";admin=true"
mac2 = MACSHA1(key)
hash2 = mac2.digest(msg+padding1+admintxt)
print("\nGenerating MAC of admin=true string without forging")
print("Message =",msg+padding1+admintxt) 
print("MAC =", hash2)
print(mac2.hexdigest(msg+padding1+admintxt))

# Let's forge the message and generate a valid MAC
# We need to know the length of the key+msg1+padding
k = b'foo'
# this is attacker's mac instance used for length extension
# the key does not matter and can be anything since we are resetting
# the registers anyway
hashload = [int.from_bytes(hash1[i:i+4], byteorder='big') for i in range(0,20,4)]
macforged = MACSHA1(k) 
# print(hashload)
# origlen is always a multiple of 64
macforged.loadstate(hashload, origlen)
hashforged = macforged.process(admintxt) # can't use digest() or hexdigest() as they add key
print("\nGenerating forged MAC")
print("Message = <previous> + <old padding> +", admintxt)
print("Forged MAC =", b''.join([x.to_bytes(4, byteorder='big') for x in hashforged]))
print(b''.join([x.to_bytes(4, byteorder='big') for x in hashforged]).hex())
