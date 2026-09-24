from Crypto.Cipher import AES
import random, base64

class SymmetricCrypto:

    @staticmethod
    def xor(x: bytes, y: bytes) -> bytes:
        # xors two byte strings and returns a byte string
        # assumes the two strings are of the same length
        z = bytes(a ^ b for a, b in zip(x, y))
        return z

    @staticmethod
    def pkcs7pad(x: bytes, blocksize=16) -> bytes:
        # Pad input using PKCS #7
        # So if there are n bytes to go before the byte string becomes
        # aligned with the block size boundary, then the bytes
        # n (in hex) will be appended n times
        # For input already aligning with the block size boundary, one full
        # block of the byte 0x10 (assuming blocksize = 16) will be appended
        padval = blocksize - (len(x) % blocksize)
        return x + (padval.to_bytes() * padval)

    @staticmethod
    def pkcs7unpad(x: bytes, blocksize=16) -> bytes:
        # Unpads input using the PKCS#7 scheme
        try:
            lastbyte = x[-1]
            # check if last byte of padding is valid
            if lastbyte > blocksize or lastbyte == 0:
                raise TypeError("Padding error!")
            # now check if every byte of padding is correct
            if (x[-lastbyte:] != (x[-1:] * lastbyte)):
                raise TypeError("Padding error!")
            unpad = x[:-lastbyte]
        except:
            raise TypeError("Padding error!")
        return unpad

    
    @staticmethod
    def AESECBencrypt(x: bytes, key: bytes) -> bytes:
        # Encrypts a block of n*16 bytes using AES
        # Assumes that block is already padded and there is at least one blk
        if ((len(x) % 16) != 0) or ((len(x) // 16) == 0):
            raise TypeError("Block size error")
        
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(x)
        return ct

    @staticmethod
    def AESECBdecrypt(x: bytes, key: bytes) -> bytes:
        # Decrypts a block of n*16 bytes using AES
        if ((len(x) % 16) != 0) or ((len(x) // 16) == 0):
            raise TypeError("Block size error")
        
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(x)
        return pt

    @staticmethod
    def AESCBCencrypt(x: bytes, key: bytes, iv: bytes) -> bytes:
        # Encrypt already padded plaintext using AES CBC mode
        # Does not check if padding is valid
        # Lets PyCryptodome check key size 
        if ((len(x) // 16) == 0):
            raise TypeError("Null plaintext provided")
        if (len(x) % 16) != 0:
            raise TypeError("Plaintext length not in multiple of 16 bytes")

        numblocks = len(x) // 16
        ct = b""
        y = iv
        for i in range(numblocks):
            ptblk = x[i*16:(i+1)*16]
            ptblk = SymmetricCrypto.xor(ptblk, y)
            ctblk = SymmetricCrypto.AESECBencrypt(ptblk, key)
            ct = ct + ctblk
            y = ctblk

        return ct

    @staticmethod
    def AESCBCdecrypt(x: bytes, key: bytes, iv: bytes) -> bytes:
        # Decrypt AES CBC mode encrypted ciphertext
        # Does not remove padding after decryption, if any
        # Lets PyCryptodome check key size
        if ((len(x) // 16) == 0):
            raise TypeError("Null ciphertext provided")
        if (len(x) % 16) != 0:
            raise TypeError("Ciphertext length multiple of 16 bytes")

        numblocks = len(x) // 16
        pt = b""
        y = iv
        for i in range(numblocks):
            ctblk = x[i*16:(i+1)*16]
            ptblk = SymmetricCrypto.AESECBdecrypt(ctblk, key)
            ptblk = SymmetricCrypto.xor(ptblk, y)
            pt = pt + ptblk
            y = ctblk

        return pt

    @staticmethod
    def encryptionoracle1(x: bytes) -> bytes:
        # Encryption oracle for Set 2 Challenge 11
        # Generates a random AES key (128 bits or 16 bytes)
        # Append 5-10 random bytes before PT and 5-10 random bytes after
        # Encrypt in ECB mode half the time, and CBC the other half
        # Input x is "attacker-controlled"
        # The idea is that the mode of operation can be detected from the ct
        pt = random.randbytes(random.randrange(5, 11))
        pt = pt + x
        pt = pt + random.randbytes(random.randrange(5, 11))
        key = random.randbytes(16)
        iv = random.randbytes(16)
        pt = SymmetricCrypto.pkcs7pad(pt, 16)
        mode = random.randrange(2)
        if mode == 0:
            # ECB mode
            cipher = AES.new(key, AES.MODE_ECB)
            ct = cipher.encrypt(pt)
        if mode == 1:
            # CBC mode
            iv = random.randbytes(16)
            ct = SymmetricCrypto.AESCBCencrypt(pt, key, iv)
        return ct

    @staticmethod
    def encryptionoracle2(x: bytes) -> bytes:
        # Oracle for Challenge 12
        # Appends "attacker-controlled" unknown string x to secret constant
        # string to be encrypted, pads, encrypt in ECB mode and output
        # the ciphertext
        # Key is a constant for this oracle
        unkstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK" # constant unknown text
        # unkstr = "bXkgdmVyeSBvd24gdGVzdCBzdHJpbmc=" # known test string "my very own test string"
        key = b'yellow submarine' # constant key
        unkstrbytes = base64.b64decode(unkstr)
        pt = x + unkstrbytes
        pt = SymmetricCrypto.pkcs7pad(pt)
        ct = SymmetricCrypto.AESECBencrypt(pt, key)
        return ct

    @staticmethod
    def encryptionoracle3(x: bytes) -> bytes:
        # Oracle for Challenge 14
        # Appends "attacker-controlled" unknown string x to secret constant
        # string to be encrypted, pads, encrypt in ECB mode and output
        # the ciphertext
        # This oracle is different from encryptionoracle2() - a randome byte
        # string of some length unknown to is prepended to the attacker's
        # chosen string
        # Key is a constant for this oracle
        unkprefix = b'w\x92+A\x9d\xdc7\x98\x17\xdc@\x9d'
        unkstr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK" # constant unknown text
        # unkstr = "bXkgdmVyeSBvd24gdGVzdCBzdHJpbmc=" # known test string "my very own test string"
        key = b'yellow submarine' # constant key
        unkstrbytes = base64.b64decode(unkstr)
        pt = unkprefix + x + unkstrbytes
        pt = SymmetricCrypto.pkcs7pad(pt)
        ct = SymmetricCrypto.AESECBencrypt(pt, key)
        return ct


    @staticmethod
    def bruteforce0(solved: bytes, targetctblock: bytes, blocksize: int) -> bytes:
        # Helper function to help solve the first block in the encryption oracle
        # solved is a 15 byte string which has been solved
        # All this function does is append one extra byte to this string,
        # try encryptions and see if it matches the target ct block provided
        for x in range(256):
            guess = solved + x.to_bytes()
            prefix = guess[-blocksize:]
            # print(prefix, len(prefix))
            guessct = SymmetricCrypto.encryptionoracle2(prefix)
            # print(guessct)
            if guessct[:blocksize] == targetctblock:
                break

        return x.to_bytes()

    @staticmethod
    def bruteforce1(unkprefixpad: bytes, solved: bytes, targetctblock: bytes, attackerblkid: int, blocksize: int) -> bytes:
        # Helper function to help solve the first block in the encryption oracle
        # solved is a 15 byte string which has been solved
        # All this function does is append one extra byte to this string,
        # try encryptions and see if it matches the target ct block provided
        for x in range(256):
            guess = solved + x.to_bytes()
            myprefix = unkprefixpad + guess[-blocksize:]
            guessct = SymmetricCrypto.encryptionoracle3(myprefix)
            # print(guessct)
            if guessct[attackerblkid*blocksize:(attackerblkid+1)*blocksize] == targetctblock:
                break

        return x.to_bytes()
