from SymmetricCrypto import MT19937 as mt

# Set 3 Challenge 23
# To tap the MT19937 rng for 624 32-bit values and use it to clone an rng

def matrixmult(M: list[int], x: int) -> int:
    # M is a GF(2) matrix that encodes list of 32 32-bit ints as bits
    # x (input) and y (output) are 32-bit ints
    y = 0
    for a in M:
        y = y << 1
        b = a & x
        b = (b ^ (b >> 16)) & 0xffff
        b = (b ^ (b >> 8)) & 0xff
        b = (b ^ (b >> 4)) & 0xf
        b = (b ^ (b >> 2)) & 0x3
        b = (b ^ (b >> 1)) & 0x1
        y = y | b
    return y

def Tinverse(z: int) -> int:
    # z is a 32-bit int - the result of the tempering function T
    # this function reverses the action of this function and produces the int
    # from the state of the rng
    c = 0xefc60000
    Ainv_int = [2164391936, 1073741824, 536870912, 270549121, 135266304, 67637280, 33554432, 16908288, 8388608, 4194304, 2113665, 1048576, 528416, 264192, 131072, 65536, 32768, 16513, 8192, 4128, 2048, 1032, 516, 256, 129, 64, 32, 16, 8, 4, 2, 1]
    Binv_int = [2147483648, 1073741824, 536870912, 268435456, 134217728, 67108864, 33554432, 16777216, 8388608, 4194304, 2097152, 2148532224, 1074266112, 537133056, 268566528, 134283264, 67141632, 33570816, 16785408, 8392704, 4196352, 2098176, 2148532736, 1074266368, 537133184, 268566592, 134283296, 67141648, 33570824, 16785412, 8392706, 4196353]
    y = z ^ (z >> 18)
    y = y ^ ((y << 15) & c)
    y = matrixmult(Ainv_int, y)
    x = matrixmult(Binv_int, y)
    return x

rng1 = mt(42)
rng1state = []
for i in range(624):
    Tx = rng1.getrand()
    x = Tinverse(Tx)
    rng1state.append(x)

# compare states
#print("constructed state")
#print(rng1state)
#print("actual state")
#st = rng1.getstate()
#print(st)
#print("comparing states: ", st == rng1state)

# initialize another clone and load state
rng2 = mt(1)
rng2.loadstate(rng1state)

# generate output from cloned state and original rng
for i in range(10):
    print("Output from original rng = ", rng1.getrand())
    print("Output from cloned rng   = ", rng2.getrand())


