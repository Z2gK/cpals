from SymmetricCrypto import CiphertextsCTR
import base64, sys

# Set 3 Challenge 19 - Break fixed-nonce CTR mode using substitutions
# Part 4 - Guess and substitute characters with higher frequencies

if len(sys.argv) != 2:
    print("Please enter filename for the CT file")
    print("Argument: <filename>")
    exit()

ctlist = []
with open(sys.argv[1], "r") as fp:
    for s in fp:
        ct = base64.b64decode(s.strip())
        ctlist.append(ct)

ciphertexts = CiphertextsCTR(ctlist)

# Guesses all belong here
# The space character has frequency of about 20% in English text
#ciphertexts.printguessbrief()
#substitutions1 = [(2, 60, " "), (10, 222, " "),
#                 (3, 46, " "), (6, 6, " "), (12, 179, " "),
#                 (14, 56, " ")]    # space characters , freqs = 9, 10, 11
substitutions1 = [(2, 60, " "), (3, 46, " "),(10, 222, " "),(12, 179, " ")]  # space characters , freqs = 9, 10, 11
# position 6,14 is not space as it leads to many characters not used in english text

substitutions2 = [(14, 56, "e")]
#substitutions2 = [(0, 114, "t"), (0, 103, "a")]  # guess most common first letters

# can try to guess "And", "and", "The", "the" for the first 3 letters of
# lines 8, 22, 24
#substitutions3 = [(1, 0x38, "h"), (2, 0x78, "e")]
# substitutions3 = [(0, 0x60, "A"), (1, 0x3e, "n")]
substitutions3 = [(0, 0x72, "A"), (1, 0x38, "n")] # Good crucial step! many thigs make sense now!!!!
# Line 1 looks like Coming, then line 3 "eighteen", line 15 "terrib-le", line 36 "casual", line 19 "voi-c-e" line 7 "meaningl-ess", line 10 "compan-ion", line 21 "beauti-ful", line 24 "hor-se", line 5 "wo-rds", line 14 "utterl-y", line 32 "wron-g", line 29 "thoug-ht" line 25 "frien-d", line 27 "en-d,", line 4 "he-ad"
substitutions3 = [(0, 0x72, "A"), (1, 0x38, "n"), (4, 0xfa, "n"), (5, 0x60, "g"), (6, 0x0c, "e"), (7, 0x73, "n"), (8, 0xa7, "l"), (9, 0x82, "e"), (11, 0x1f, "g"), (13, 0xf7, "c"), (15, 0x60, "e"), (16, 0xe6, "s"), (17, 0xc4, "s"), (18, 0x90, "i"), (19, 0xd7, "o"), (20, 0xc8, "n"), (21, 0x99, "f"), (22, 0x1b, "u"), (23, 0x37, "l"), (24, 0xc8, "r"), (25, 0xc6,"d"),(26,0x3d,"s"), (27, 0x9d,"y"), (28, 0x64, "g"), (29, 0xeb, "h"),(30, 0x9d,"t"), (31, 0x67, "d"),(32,0x36,"d"), (33,0x10,","), (34,0xe8,"a"),(35,0x1f,"d") ]
#substitutions3 = []

substitutions = substitutions1 + substitutions2 + substitutions3
ciphertexts.substituteV(substitutions)
ciphertexts.printguessbrief()
