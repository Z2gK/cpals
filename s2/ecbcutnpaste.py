from SymmetricCrypto import SymmetricCrypto as sc

# Set 2 Challenge 13 - ECB cut and paste
# Scenario:
# Attacker controls input to profile_for()
# Backend, profile_for() generates dict object, passes it to encoder,
# encodes it into cookie format, encrypts it using ECB mode using the same
# key each time, and returns ciphertext to attacker
# Attacker is able to modify ciphertext, sends it to some authorization
# service and obtain privileges
# In summary:
# Attacker inputs email -> profile_for -> encryptprofile -> ciphertext
# Attacker modifies ciphertext -> decryptprofile
# encryptprofile(profile_for()) is the oracle accessible by the attacker

def profile_for(email: str) -> dict:
    # takes an input string, sanitizes it and assigns it as the email address
    # returns fields in cookie format
    email = email.replace("=","")
    email = email.replace("&","")
    d = {"email": email, "uid": 10, "role": "user"}
    encoded = f"email={d['email']}&uid={d['uid']}&role={d['role']}"
    return encoded

def parsecookie(cookiestr: str) -> dict:
    # parses cookie string and returns dict object
    d = {}
    try:
        s = cookiestr.split("&")
        for item in s:
            t = item.split("=")
            if t[0] == "email":
                d["email"] = t[1]
            if t[0] == "uid":
                d["uid"] = t[1]
            if t[0] == "role":
                d["role"] = t[1]
    except:
        raise TypeError("Malformed cookie string!")

    return d

def encryptprofile(s: str) -> bytes:
    # Encrypts profile in cookie string format and returns ct
    key = b'yellow submarine'
    pt = s.encode()
    pt = sc.pkcs7pad(pt)
    ct = sc.AESECBencrypt(pt,key)
    return ct

def decryptprofile(ct: bytes) -> dict:
    # Decrypt encrypted profile and returns dict object
    key = b'yellow submarine'
    pt = sc.AESECBdecrypt(ct, key)
    pt = sc.pkcs7unpad(pt)
    d = parsecookie(pt.decode())
    return d


# Assume we already know that the blocksize = 16
# first send pt to get encryption of 'admin\x0b..\x0b' in second block of ct
# 'foo@bar.co' is 10 bytes so that email=foo@bar.co is 16 bytes long
email = 'foo@bar.coadmin'
email = email + "\x0b"*11
ct1 = encryptprofile(profile_for(email))
print(ct1)
finalctblk = ct1[16:32]

# Now create the admin profile for email foooo@bar.com
# We need to align user with the last block
# These are 16 byte blocks:
# email=foooo@bar.
# com&uid=10&role=
# the final block with the 'user' string will be cut off and replaced with
# the admin ciphertext stiched on
email = "foooo@bar.com"
ct2 = encryptprofile(profile_for(email))
modct = ct2[:-16] + finalctblk
print(ct2,len(ct2))
print(modct,len(modct))

# Finally, decrypt profile and see if it's successful
d = decryptprofile(modct)
print(d)
