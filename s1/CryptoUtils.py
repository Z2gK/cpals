import base64

class CryptoUtils:
    # From https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    # Letters with the highest frequencies in English text
    ENGLISHLETTERSORTED = "ETAOINSRHDLUCMFYWGPBVKXQJZ"
    
    @staticmethod
    def hextob64(hexencodedstr: str) -> str:
        # Accepts a hex string and returns a base64 encoded string
        return base64.b64encode(bytes.fromhex(hexencodedstr)).decode("utf-8")

    @staticmethod
    def bytestohex(x: bytes) -> str:
        return x.hex()

    @staticmethod
    def hextobytes(s: str) -> bytes:
        return bytes.fromhex(s)
    
    @staticmethod
    def xor(x: bytes, y: bytes) -> bytes:
        # xors two byte strings and returns a byte string
        # assumes the two strings are of the same length
        z = bytes(a ^ b for a, b in zip(x, y))
        return z
        
    @staticmethod
    def xorhex(hexencodedstr1: str, hexencodedstr2: str) -> str:
        # xors two hex encoded strings and returns the result
        # b1 = bytes.fromhex(hexencodedstr1)
        # b2 = bytes.fromhex(hexencodedstr2)
        b1 = CryptoUtils.hextobytes(hexencodedstr1)
        b2 = CryptoUtils.hextobytes(hexencodedstr2)
        b3 = bytes(a ^ b for a, b in zip(b1, b2))
        return b3.hex()

    
    @staticmethod
    def englishletterfreqs(bstring: bytes) -> list[int]:
        # Accepts a byte string and returns a list of letter frequencies (ints)
        # Counts both upper and lowercase letters - 26 altogether
        # Ignores non-English characters        
        letterfreqs = {a:0 for a in CryptoUtils.ENGLISHLETTERSORTED}
        for b in bstring:
            if ((b <= 90) and (b >= 65)) or ((b<=122) and (b >= 97)):
                letterfreqs[chr(b).upper()] = letterfreqs[chr(b).upper()] + 1
        freqlist = []
        for c in CryptoUtils.ENGLISHLETTERSORTED:
            freqlist.append(letterfreqs[c])
        # freqlist is the list of frequencies for "ETOAINSH..." in that order
        # this list has 26 entries in total
        return freqlist
            
    @staticmethod
    def bytefreqs(bstring: bytes) -> list[int]:
        # Accepts a byte string and returns a list of frequencies (ints)
        # of the various bytes
        bytefreqs = [0] * 256
        for b in bstring:
            bytefreqs[b] = bytefreqs[b] + 1
        return bytefreqs

    @staticmethod
    def alphabetscore(bstring: bytes) -> float:
        # A very basic metric to determine if decrypted text is composed from
        # mostly English alphabets and space
        # Counts the number of spaces and English letters [A-Za-z],
        # divide by the length of string and returns the score
        count = 0
        for b in bstring:
            if ((b <= 90) and (b >= 65)) or ((b<=122) and (b >= 97)) or (b == 32):
                count += 1
        return (count * 1.0) / len(bstring)
        pass

    @staticmethod
    def vigenere(pt: bytes, key: bytes) -> bytes:
        # Implements Vigenere (repeating key) encryption
        # This same function is used for decryption
        fullkey = key * (1 + len(pt) // len(key))
        fullkey = fullkey[:len(pt)]
        return CryptoUtils.xor(pt, fullkey)

    @staticmethod
    def hamming(x: bytes, y: bytes) -> int:
        # Returns the hamming distance of two byte strings
        # This is defined as the number of differing bits
        if (len(x) != len(y)):
            raise TypeError("Inputs need to be of the same length")

        count = 0
        for a, b in zip(x, y):
            c = a ^ b
            while (c != 0):
                count = count + (c & 0x1)
                c = c >> 1
        return count

    @staticmethod
    def vigeneresplit(ct: bytes, keysize: int) -> list[bytes]:
        # Takes ciphertext and splits it up into 'keysize' number of
        # byte strings suitable for vigenere cryptanalysis
        splitctlist = [ b'' ] * keysize
        for index, x in enumerate(ct, start=0):
            splitctlist[index % keysize] = splitctlist[index % keysize] + x.to_bytes()
        return splitctlist

    @staticmethod
    def trysinglebytexor(ct: bytes, threshold=0.9) -> list[tuple[float, int, bytes]]:
        # Takes a byte string as input and tries all 256 possibilities for
        # constant byte xor
        # Then use alphabetscore as metric and output only those where
        # score > threshold (default is 0.9)
        # Output is a list of tuples, where each tuple is of the format
        # (score, byte(int), pt)
        # freqscorelist = [0]*256
        # xoredlist = []
        # maxalphabetscore = 0.0
        pt = None
        candidates = []
        for x in range(256):
            keystream = bytes([x]*len(ct)) # form the new string to xor
            pt = CryptoUtils.xor(ct, keystream) # 'decrypted' string
            # xoredlist.append(pt)
            ascore = CryptoUtils.alphabetscore(pt)
            if (ascore >= threshold):
                candidates.append((ascore, x, pt))
        return candidates

    @staticmethod
    def detectrepeatedblocks(ct: bytes) -> set[bytes]:
        # Takes a byte string as input and detects if there are any repeated
        # 128-bit blocks
        if (len(ct) % 16 != 0):
            raise TypeError("Length of byte string is not a multiple of 128-bit")
        seenblocks = set([])
        repeatedblocks = set([])
        numblocks = len(ct) // 16
        for i in range(numblocks):
            currentblock = ct[i*16:(i+1)*16]
            if currentblock in seenblocks:
                repeatedblocks.add(currentblock)
            else:
                seenblocks.add(currentblock)
        return repeatedblocks
