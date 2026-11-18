from SymmetricCrypto import MACMD4

# Set 4 Challenge 30 - Break an MD4 keyed MAC using length extension

def padding(msg):
    # Returns padding of msg
    # Intention is to pad so that we have chunks of 512 bits (64 bytes)
    # The last 8 bytes is the length of the original message in little endian
    pad = b""
    length = (len(msg) * 8).to_bytes(8, byteorder="little", signed=False)
    msg += b'\x80'
    pad += b'\x80'
    # msg += bytes((56 - len(msg) % 64) % 64)
    pad += bytes((56 - len(msg) % 64) % 64)
    # msg += length
    pad += length
    return pad
    
# Testing the hash
k = b''
mac = MACMD4(k)
#s = b"The quick brown fox jumps over the lazy dog"
s = b"The quick brown fox jumps over the very very very very very very very\
 lazy dog..."
print("Message =", k+s)
print("MD4 MAC =")
print(mac.digest(s))
print(mac.hexdigest(s))

# Compute for the base case
key = b"A" * 16
msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
mac0 = MACMD4(key)
print("\nGenerating MAC for the base case")
print("Message =", msg)
hash0 = mac0.digest(msg)
print("MAC = ", hash0)
print(mac0.hexdigest(msg))
# print("Padding from padding() =", padding(key+msg))
# verified to be this using cyberchef
# c84fd2ee8705d129d6b64dc2a998ee4a



# Compute the correct MAC of the tampered msg without length extension
print("\nGenerating MAC of admin=true string without forging")

key = b"A" * 16
msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
admintxt = b";admin=true"
padding1 = padding(key+msg)
mac1 = MACMD4(key)
hash1 = mac1.digest(msg+padding1+admintxt)
print("Message =",msg+padding1+admintxt) 
print("MAC =", hash1)
print(mac1.hexdigest(msg+padding1+admintxt))
origlen = len(key) + len(msg) + len(padding1)
# print(origlen)
# verified with cyberchef to be
# 493262e80d2bd0ba1d66573170528e79


# Let's forge the message and generate a valid MAC
# We need to know the length of the key+msg1+padding
print("\nGenerating forged MAC")
k = b'foo'
# this is attacker's mac instance used for length extension
# the key does not matter and can be anything since we are resetting
# the registers anyway
# Note that little endian is used for MD4
# print("The hash value to load:")
# take hash0 from the base case
hashload = [int.from_bytes(hash0[i:i+4], byteorder='little') for i in range(0,16,4)]
# print(hashload)
macforged = MACMD4(k)
macforged.loadstate(hashload, origlen)
hashforged = macforged.process(admintxt)
print("Message = <previous> + <old padding> +", admintxt)
print("Forged MAC =", b''.join([x.to_bytes(4, byteorder='little') for x in hashforged]))
print(b''.join([x.to_bytes(4, byteorder='little') for x in hashforged]).hex())

