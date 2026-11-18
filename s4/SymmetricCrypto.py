from Crypto.Cipher import AES
import random, base64, os

class SymmetricCrypto:

    @staticmethod
    def xor(x: bytes, y: bytes) -> bytes:
        # xors two byte strings and returns a byte string
        # assumes the two strings are of the same length
        z = bytes(a ^ b for a, b in zip(x, y))
        return z

    @staticmethod
    def bytestohex(x: bytes) -> str:
        return x.hex()

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
    def int2d64le(n: int) -> bytes:
        # Convert unsigned integer to 16 byte (128 bit) string consisting of
        # 2 little endian 64 bit words L | R, with R being the word
        # representing the lesser of the two words
        if n < 0:
            raise ValueError
        r = n & 0xffffffffffffffff
        l = (n >> 64) & 0xffffffffffffffff
        R = r.to_bytes(8, byteorder='little')
        L = l.to_bytes(8, byteorder='little')
        return L + R

    @staticmethod
    def d64le2int(x: bytes) -> int:
        # Convert 16-byte string to integer
        # Assumes input to be of the format L | R, where L and R are 64-bit
        # little endian words, with R being the lesser of the two in sig
        # This would be the inverse function of int2d64le
        if len(x) != 16:
            raise ValueError
        L = x[:8]
        R = x[8:]
        n = int.from_bytes(R, byteorder='little')
        n = n + (int.from_bytes(L, byteorder='little') << 64)
        return n
    
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
            raise TypeError("Ciphertext length not in multiple of 16 bytes")

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


    def AESCTRencrypt(x: bytes, key: bytes, nonce: bytes) -> bytes:
        # Encrypts some PT x using AES CTR mode
        if len(x) == 0:
            raise TypeError("Empty PT provided")
        numblocks = len(x) // 16
        if (len(x) % 16) != 0:
            numblocks = numblocks + 1
        ct = b''
        for i in range(numblocks):
            ptblk = x[i*16:(i+1)*16]
            keystreamblk = SymmetricCrypto.AESECBencrypt(nonce, key)
            ct = ct + SymmetricCrypto.xor(ptblk,keystreamblk[:len(ptblk)])
            n = SymmetricCrypto.d64le2int(nonce)
            n = n + 1
            nonce = SymmetricCrypto.int2d64le(n)
        return ct

    def AESCTRdecrypt(x: bytes, key: bytes, nonce: bytes) -> bytes:
        # Decrypts some CT x using the AES CTR mode
        # Encryption and decryption uses the same function in CTR mode
        return SymmetricCrypto.AESCTRencrypt(x, key, nonce)

    
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


class RndAccessCTR:
    # class to store random access AES CTR mode encrypted ciphertexts
    # for Set 4 Challenge 25
    # key and nonce are both 16 bytes
    def __init__(self, pt: bytes, key: bytes, nonce: bytes):
        self.key = key
        self.nonce = nonce
        self.ct = SymmetricCrypto.AESCTRencrypt(pt, key, nonce)

    def printct(self):
        print(self.ct)

    def printcthex(self):
        print(self.ct.hex())

    def getct(self):
        return self.ct

    def edit(self, offset: int, newtext: bytes):
        # offset is the position where bytes starts to be replaced
        # first byte offset=0
        if offset >= len(self.ct) or offset < 0:
            print("Invalid offset!")
            raise ValueError

        if offset + len(newtext) > len(self.ct):
            print("New text is too long")
            raise ValueError

        if len(newtext) == 0:
            return

        pt = SymmetricCrypto.AESCTRdecrypt(self.ct, self.key, self.nonce)
        pt = pt[:offset] + newtext + pt[offset+len(newtext):]
        self.ct = SymmetricCrypto.AESCTRencrypt(pt, self.key, self.nonce)
        
        
    
class CiphertextsCTR:
    # class to store AES CTR mode encrypted ciphertexts
    # for Set 3 Challenge 19
    def __init__(self, ctlist: list[bytes]):
        self.cts = ctlist
        self.substitutionsV = [] # vertical substitutions [(pos, byte, char),... ]
        self.columnkeys = [] # keystream bytes in columns [(col1, byte1),...]
        self.guess = []  # character by character guesses
        for c in self.cts:
            self.guess.append([""] * len(c))
        self.width = self.maxctlen()  # length of longest CT
        self.numbytesincols = [0] * self.width # keeps tabs of # bytes in each col
        self.getnumbytesincols() # fill self.numbytesincols

    def getcts(self):
        # return list of ciphertexts in raw byte format
        return self.cts

    def minctlen(self):
        # return the mininum length of ciphertext
        a = [len(c) for c in self.cts]
        return min(a)

    def maxctlen(self):
        # return the maximum length of ciphertext
        a = [len(c) for c in self.cts]
        return max(a)

    def getnumbytesincols(self):
        # updates self.numbytesincols with number of bytes in each column
        # self.numbytesincols[n] = number of bytes in col n at the end of this
        # function
        for c in self.cts:
            v = ([1] * len(c)) + ([0] * self.width)
            self.numbytesincols = [x + y for x, y in zip(self.numbytesincols, v)]

    def getcol(self, col: int) -> bytes:
        # return bytes in column col (=0, 1, ..., width-1)
        if col >= self.width:
            raise ValueError
        x = b''
        for ct in self.cts:
            if col < len(ct):
                x = x + ct[col].to_bytes()
        return x
    
    def printguessbrief(self):
        # print strings with guesses in brief format
        numwidth = len(str(len(self.cts) - 1))
        fmt = str(numwidth) + "d"
        for idx, s in enumerate(self.guess):
            s_ = ["_" if c == "" else c for c in s]
            print(f"{idx:{fmt}}:", "".join(s_))
            # print("".join(s_))

    def trykeys(self, keylist: list[tuple]):
        # try to decrypt columns using list of key bytes assigned for
        # specific columns
        # input format: [(col1, byte), (col2, byte2), ...]
        self.columnkeys = keylist
        for col, x in keylist:
            for idx, ct in enumerate(self.cts):
                if (col < len(ct)) and (self.guess[idx][col] == "") :
                    self.guess[idx][col] = (ct[col] ^ int.from_bytes(x)).to_bytes().decode()

    def substituteV(self, substlist: list[tuple]):
        # perform substitution
        # substitution list format: [(col, byte (int), char),... ]
        # also calculates the implied key stream byte and tries to decrypt
        # CT bytes in the same column
        self.substitutionsV = substlist
        # newer implementation to decrypt bytes in entire column
        for s in self.substitutionsV:
            #keybyte = SymmetricCrypto.xor(s[1], bytes(s[2], 'utf-8'))
            keybyte = int.to_bytes(s[1] ^ ord(s[2]))
            for idx, ct in enumerate(self.cts):
                if s[0] < len(ct):
                    self.guess[idx][s[0]] = chr(int.from_bytes(keybyte) ^ ct[s[0]])
        # older implementation
        #for idx, ct in enumerate(self.cts):
        #    for s in self.substitutionsV:
        #        if ct[s[0]] == s[1]:
        #            self.guess[idx][s[0]] = s[2]

    def getsubstitutionsV(self):
        return self.substitutionsV
    
    def reset(self):
        # clear all substitutions and key guesses
        self.substitutionsV = []
        self.columnkeys = []
        self.guess = []
        for c in self.cts:
            self.guess.append([""] * len(c))
    
    def printcts(self):
        # pretty print ciphertexts in hex
        rulerstr = " 0 1 2 3 4 5 6 7 8 9 "
        maxctlen = max([len(c) for c in self.cts])
        blocks10 = maxctlen // 10
        if ((maxctlen % 10) != 0):
            blocks10 = blocks10 + 1
        rulerstr = rulerstr * blocks10
        numwidth = len(str(len(self.cts) - 1))
        fmt = str(numwidth) + "d"
        fullruler = (" " * numwidth) + "   " + rulerstr
        print(fullruler)
        for idx, s in enumerate(self.cts):
            h = SymmetricCrypto.bytestohex(s)
            h = [h[i:i+20] for i in range(0, len(h),20)]
            h = " ".join(h)
            print(f"{idx:{fmt}} :", h)
        pass
    


class PaddingOracle:
    # Padding oracle for Set 3 Challenge 17
    def __init__(self):
        unkstrings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
        b64string = random.choice(unkstrings)
        self.pt = base64.b64decode(b64string)
        # self.pt = b"the quick brown fox jumps over the lazy dog"
        self.key = os.urandom(16) # use 128 bit key
        self.iv = os.urandom(16)
        #self.key = b'yellow submarine'
        #self.iv = b'AAAAAAAAAAAAAAAA'
        self.pt = SymmetricCrypto.pkcs7pad(self.pt)
        self.ct = SymmetricCrypto.AESCBCencrypt(self.pt, self.key, self.iv)

    def getctiv(self):
        return (self.ct, self.iv)

    def decrypt(self, x: bytes, iv: bytes) -> bool:
        decrypted = SymmetricCrypto.AESCBCdecrypt(x, self.key, iv)
        goodpadding = True
        try:
            ct = SymmetricCrypto.pkcs7unpad(decrypted)
        except:
            goodpadding = False

        return goodpadding

class MT19937:
    # Mersenne Twister MT19937 RNG for Set 3 Challenges 21-24
    mask32 = 0xffffffff
    w = 32
    r = 31
    n = 624
    m = 397
    f = 1812433253 # "not part of the algorithm proper"
    a = 0x9908b0df

    u = 11
    d = 0xffffffff
    s = 7
    b = 0x9d2c5680
    t = 15
    c = 0xefc60000
    l = 18
    
    umask = (mask32 << r) & mask32
    lmask = (mask32 >> (w-r)) & mask32
    
    def __init__(self, seed: int = 1):
        mask32 = MT19937.mask32
        n = MT19937.n
        f = MT19937.f
        w = MT19937.w
        seed = seed & mask32
        
        self.state = [0] * n
        self.state[0] = seed

        # initialize state, need to keep state 32-bit
        for i in range(1,n):
            self.state[i] = f * (self.state[i-1] ^ (self.state[i-1] >> (w-2))) + i
            self.state[i] = self.state[i] & mask32

    def getrand(self):
        # Generate 32-bit random number
        m = MT19937.m
        # r = MT19937.r
        a = MT19937.a
        umask = MT19937.umask
        lmask = MT19937.lmask
        u = MT19937.u
        d = MT19937.d
        s = MT19937.s
        b = MT19937.b
        t = MT19937.t
        c = MT19937.c
        l = MT19937.l
        
        x = (self.state[0] & umask) | (self.state[1] & lmask)
        xA = x >> 1
        if (x & 0x1) == 1:
            xA = xA ^ a
        #print("xA = ", xA)
        x_ = self.state[m] ^ xA # the new value of the state
        self.state.append(x_)
        self.state.pop(0)
        
        # Apply T
        y = x_ ^ ((x_ >> u) & d)
        #print("y1 = ", y)
        y = y ^ ((y << s) & b)
        #print("y2 = ", y)
        y = y ^ ((y << t) & c)
        #print("y3 = ", y)
        z = y ^ (y >> l)

        return z

    def encrypt(self, pt: bytes) -> bytes:
        # treat rng as a stream cipher and encrypt a certain input
        # take the 8 LSB of each 32-bit output and treat it as a keystream byte
        if len(pt) == 0:
            print("PT cannot be zero length")
            raise ValueError
        
        prefix = random.randbytes(random.randrange(1, 21)) # len of random prefix
        pt = prefix + pt
        n = len(pt)
        keystream = b''
        for i in range(n):
            keystream = keystream + (self.getrand() & 0xff).to_bytes()
        ct = SymmetricCrypto.xor(keystream, pt)
        return ct
    
    def loadstate(self, s: list[int]):
        # load 624 32-bit internal state
        if len(s) != 624:
            print("Invalid internal state")
            raise ValueError
        self.state = s

    def getstate(self):
        return self.state
    
    def printstate(self):
        # print the entire internal state
        print(self.state)

class MACSHA1:
    # Implements SHA1 MAC in pure python
    # Adapted from the implementation here:
    # https://gist.github.com/kangtastic/af9fe725c2358463035a0637b9fee5c4
    # The instance does not maintain state
    def __init__(self, key: bytes):
        self.key = key
        self.stateloaded = False
        # self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def digest(self, msg) -> bytes:
        # prepends MAC key, hash and return hash as byte string
        # we expect msg to be bytes, but can take str too
        if (type(msg) != str) and (type(msg) != bytes):
            print("Message should be a text or byte string!")
            raise TypeError
        if type(msg) == str:
            msg = msg.encode()
        h = self.process(self.key + msg)
        return b''.join([x.to_bytes(4, byteorder='big') for x in h])
        # return hashlib.sha1(self.key + msg).digest()

    def hexdigest(self, msg) -> str:
        # prepends MAC key, hash and return hash as hex encoded string
        # we expect msg to be bytes, but can take str too
        if (type(msg) != str) and (type(msg) != bytes):
            print("Message should be a text or byte string!")
            raise TypeError
        if type(msg) == str:
            msg = msg.encode()
        h = self.process(self.key + msg)
        return b''.join([x.to_bytes(4, byteorder='big') for x in h]).hex()
        # return hashlib.sha1(self.key + msg).hexdigest()

    def loadstate(self, h: list[int], start: int):
        # enable loading of state to facilitate length extension computation
        # h should be a list of 5 32-bit ints
        # start is the number of bytes already hashed
        self.h = h
        self.stateloaded = True
        self.start = start
        
    def process(self, msg):
        # implements SHA1 without prepending the MAC key
        # we expect msg to be bytes, but can take str too
        if (type(msg) != str) and (type(msg) != bytes):
            print("Message should be a text or byte string!")
            raise TypeError
        if type(msg) == str:
            msg = msg.encode()

        if self.stateloaded:
            # length extension case
            h = self.h
            ml = (len(msg) + self.start) * 8
            msg += b"\x80"
            msg += b"\x00" * (-(len(msg) + self.start + 8) % 64) # actually don't need to add self.start since it is 0 mod 64 
            msg += ml.to_bytes(8, byteorder='big')
        else:
            # normal case
            h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
            ml = len(msg) * 8
            msg += b"\x80"
            msg += b"\x00" * (-(len(msg) + 8) % 64)
            # msg += struct.pack(">Q", ml)
            msg += ml.to_bytes(8, byteorder='big') # more Pythonic

        chunks = [msg[i : i + 64] for i in range(0, len(msg), 64)]
        for chunk in chunks:
            # w = list(struct.unpack(">16L", chunk))
            w = [int.from_bytes(chunk[i:i+4], "big") for i in range(0,64,4)] # more Pythonic

            # Extend the sixteen 32-bit words into eighty 32-bit words.
            for i in range(16, 80):
                value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w.append(MACSHA1.lrot(value, 1))

            # Initialize hash value for this chunk.
            a, b, c, d, e = h

            # Main loop.
            for i in range(len(w)):
                if i < 20:
                    f, k = d ^ (b & (c ^ d)), 0x5A827999
                elif i < 40:
                    f, k = b ^ c ^ d, 0x6ED9EBA1
                elif i < 60:
                    f, k = (b & c) | (d & (b | c)), 0x8F1BBCDC
                else:
                    f, k = b ^ c ^ d, 0xCA62C1D6

                temp = (MACSHA1.lrot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e, d, c, b, a = d, c, MACSHA1.lrot(b, 30), a, temp

            # Add this chunk's hash to result so far.
            c_hash = [a, b, c, d, e]
            h = [((v + n) & 0xFFFFFFFF) for v, n in zip(h, c_hash)]
        return h

    @staticmethod
    def lrot(value, n):
        mask = 0xFFFFFFFF
        width = 32
        lbits = (value << n) & mask
        rbits =  value >> (width - n)
        return lbits | rbits
        
    def auth(self, msg, mac) -> bool:
        # authenticates message
        # return True if message authenticates, False otherwise
        # mac can either be bytes or hex-encoded string
        if (type(msg) != str) and (type(msg) != bytes):
            print("Message should be a text or byte string!")
            raise TypeError
        if (type(mac) != str) and (type(mac) != bytes):
            print("MAC should be a text or byte string!")
            raise TypeError
        if type(mac) == str and len(bytes.fromhex(mac)) != 20:
            print("Invalid MAC!")
            raise TypeError
        if type(mac) == bytes and len(mac) != 20:
            print("Invalid MAC!")
            raise TypeError

        # Convert both msg and mac to byte strings
        if type(msg) == str:
            msg = msg.encode()
        if type(mac) == str:
            mac = bytes.fromhex(mac)

        return self.digest(msg) == mac

class MACMD4:
    # Implements MD4 in pure Python
    # Adapted from the implementation here:
    # https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py
    # This implementation does not maintain state
    def __init__(self, key: bytes):
        self.key = key
        self.stateloaded = False
        
    def loadstate(self, h: list[int], start: int):
        # enable loading of state to facilitate length extension computation
        # h should be a list of 4 32-bit ints
        # start is the number of bytes already hashed
        self.h = h
        self.stateloaded = True
        self.start = start

    def digest(self, msg: bytes) -> bytes:
        msg = self.key + msg
        h = self.process(msg)
        # print(h)
        return b''.join([v.to_bytes(4, 'little') for v in h])

    def hexdigest(self, msg: bytes) -> str:
        msg = self.key + msg
        h = self.process(msg)
        return b''.join([x.to_bytes(4, 'little') for x in h]).hex()

    def process(self, msg: bytes):
        if self.stateloaded:
            # print("State loaded!")
            length = ((len(msg) + self.start) * 8).to_bytes(8, byteorder="little", signed=False)
            msg += b'\x80'
            msg += bytes((56 - len(msg)) % 64) # no need to add self.start since it will be 0 mod 64 anyway
            msg += length
            # print(msg)
            h = self.h
        else:
            # length = struct.pack('<Q', len(msg) * 8)
            length = (len(msg) * 8).to_bytes(8, byteorder="little", signed=False)
            msg += b'\x80'
            msg += bytes((56 - len(msg)) % 64)
            msg += length
            # print(msg)
            h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

        while len(msg) != 0:
            h = self._handle(msg[:64], h)
            msg = msg[64:]
        return h

    def _handle(self, chunk: bytes, h):
        # X = list(struct.unpack('<' + 'I' * 16, chunk))
        # print("start h =", h)
        X = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, 64, 4)]
        # AA, BB, CC, DD = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        A, B, C, D = h
        # A, B, C, D = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = MACMD4.lrot((A + MACMD4._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = MACMD4.lrot((D + MACMD4._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = MACMD4.lrot((C + MACMD4._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = MACMD4.lrot((B + MACMD4._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = MACMD4.lrot((A + MACMD4._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = MACMD4.lrot((D + MACMD4._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = MACMD4.lrot((C + MACMD4._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = MACMD4.lrot((B + MACMD4._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = MACMD4.lrot((A + MACMD4._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = MACMD4.lrot((D + MACMD4._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = MACMD4.lrot((C + MACMD4._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = MACMD4.lrot((B + MACMD4._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        h[0] = (h[0] + A) & 0xffffffff
        h[1] = (h[1] + B) & 0xffffffff
        h[2] = (h[2] + C) & 0xffffffff
        h[3] = (h[3] + D) & 0xffffffff
        # print("end h =", h)
        return h

    @staticmethod
    def lrot(x, n):
        return (x << n) | (x >> (32 - n))

    @staticmethod
    def _F(x,y,z):
        return ((x & y) | (~x & z))

    @staticmethod
    def _G(x,y,z):
        return ((x & y) | (x & z) | (y & z))

    @staticmethod
    def _H(x,y,z):
        return (x ^ y ^ z)

