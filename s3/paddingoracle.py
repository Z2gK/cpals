from SymmetricCrypto import PaddingOracle as pd
from CryptoUtils import CryptoUtils as cu

class ProcessingError(Exception):
    # raised when padding oracle attack fails and cannot identify a certain byte
    pass

# Set 3 Challenge 17 - The CBC padding oracle

# Key and iv which are to be chosen at random on object instantiation but
# remain constant for the instance
# PT to be encrypted is chosen internally within class instance upon object
# instantiation
cipher = pd()
ct, iv = cipher.getctiv()
print("Ciphertext:")
print(ct, len(ct))
print("IV:")
print(iv, len(iv))


# Padding oracle attack (PKCS#7) starts from the rightmost byte of the
# targeted pt
# Tampering with block i of ct would affect block i+1 of pt
# To solve block 0 of pt, we need to tamper with the iv
def paddingoracleattack(c: PaddingOracle, blkid: int) -> bytes:
    # attacks block blkid (index from 0) and returns the pt for that block
    # assumes block size is 16
    ct, iv = c.getctiv()
    if not( (blkid + 1)*16 <= len(ct) ):
        raise IndexError
    numblocks = len(ct) // 16
    # this is the block to be tampered with
    if (blkid != 0):
        origctblk = ct[(blkid-1)*16:blkid*16]
    else:
        origctblk = iv # case where we attack pt block 0
    solved = b'' # stores the solved pt

    for paddingval in range(1,17):
        endpadxor = cu.xor(solved, paddingval.to_bytes() * (paddingval -1)) # solved xor paddingval
        endpadxor = b'\x00' * (16-len(solved)) + endpadxor
        dlist = []
        for d in range(256):
            diffblk = b'\x00' * (16-paddingval) + d.to_bytes() + b'\x00' * (paddingval-1)
            # print(diffblk)
            ctblkmod = cu.xor(origctblk, diffblk) # this would be the iv if attacking blkid = 0
            ctblkmod = cu.xor(ctblkmod, endpadxor)
            # print(ctblkmod)
            if (blkid != 0):
                fullct = ct[:(blkid-1)*16] + ctblkmod + ct[blkid*16:(blkid+1)*16]
                paddingok = cipher.decrypt(fullct,iv)
            else:
                fullct = ct[:16]
                paddingok = cipher.decrypt(fullct, ctblkmod)

            if paddingok:
                if paddingval == 1:
            # perform additional byte-before check only when attacking final byte
                    ctblkmod = cu.xor(ctblkmod, b'\x00' * 14 + b'\x01' + b'\x00')
                    if blkid != 0:
                        fullct = ct[:(blkid-1)*16] + ctblkmod + ct[blkid*16:]
                        paddingok = cipher.decrypt(fullct,iv)
                    else:
                        fullct = ct[:16]
                        paddingok = cipher.decrypt(fullct,ctblkmod)

                    if paddingok:
                        dlist.append(d)
                else: 
                    dlist.append(d)

        if (len(dlist) == 1):
            solved = (dlist[0] ^ paddingval).to_bytes() + solved
        else:
            raise ProcessingError("Unable to determine plaintext byte")

    # print(solved)
    return solved

pt = b''
numblocks = len(ct) // 16
for i in range(numblocks-1, -1, -1):
    ptblk = paddingoracleattack(cipher,i)
    pt = ptblk + pt

print("Solved PT:")
print(pt)

