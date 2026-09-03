from CryptoUtils import CryptoUtils as cu
import sys

# Set 1 Challenge 8

# Read a file containing encrypted data and detect the line that may be
# encrypted using AES-ECB
if len(sys.argv) != 2:
    print("Detect line encrypted using AES-ECB")
    print("Arguments: <filename (hex-encoded file)>")
    exit()

fname = sys.argv[1]
with open(fname, "r") as fp:
    for index, line in enumerate(fp, start=0):
        ct = cu.hextobytes(line.strip())
        #print(index)
        #print(ct)
        #print(len(ct))
        repeatedblocks = cu.detectrepeatedblocks(ct)
        if repeatedblocks:
            print(f"Ciphertext {index} may be ECB encrypted")
            print("Repeated blocks:")
            print(repeatedblocks)
            for x in repeatedblocks:
                print(cu.bytestohex(x))
            print("Original line:")
            print(line)
