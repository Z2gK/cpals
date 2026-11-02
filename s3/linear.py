import galois
import numpy as np

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

def T(x_: int) -> int:
    u = 11
    d = 0xffffffff
    s = 7
    b = 0x9d2c5680
    t = 15
    c = 0xefc60000
    l = 18
    
    y = x_ ^ ((x_ >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    z = y ^ (y >> l)
    return z

# constants for MT19937
#    u = 11
#    d = 0xffffffff
#    s = 7
#    b = 0x9d2c5680
#    t = 15
#    c = 0xefc60000
#    l = 18

# Apply T - the original tempering function
# Step 1
#y = x_ ^ ((x_ >> u) & d)
# inverse: ??

# Step 2 - need linear algebra tool to find inverse
#y = y ^ ((y << s) & b)
# inverse: ??

# Step 3
#y = y ^ ((y << t) & c)
# inverse: y ^ ((y << 15) & c)

# Step 4
#z = y ^ (y >> l)
# inverse: z ^ (z >> 18)


# Compute inverse matrix for Step 2
A = galois.GF2.Identity(32)
Aident_int = []
for line in A.tolist():
    linestr = [str(x) for x in line]
    Aident_int.append(int("".join(linestr),2))
#print(Aident_int)
#print([hex(x) for x in Aident_int])

# Construct the matrix for Step 2
# fill in off-diagonal entries
# A(0,7), A(1,8), A(2,9)...A(??,31) are 1 or 0 according to bits of b
i = 0
b = 0x9d2c5680
for j in range(7, 32):
    if (b & 0x80000000) != 0:
        A[i][j] = 1
    b = b << 1
    i = i+1
A_int = []
for line in A.tolist():
    linestr = [str(x) for x in line]
    A_int.append(int("".join(linestr),2))
print("Matrix for Step 2:")
print(A_int)


# Construct the inverse matrix for Step 2
Ainv = np.linalg.inv(A)
# print(Ainv)
Ainv_l = Ainv.tolist()
Ainv_int = []
for line in Ainv_l:
    # print(line)
    linestr = [str(x) for x in line]
    Ainv_int.append(int("".join(linestr),2))
print("Inverse matrix for Step 2:")
print(Ainv_int)
#Ainv_hex = [hex(x) for x in Ainv_int]
#print(Ainv_hex)

# Computed inverse matrix for Step 2
# [2164391936, 1073741824, 536870912, 270549121, 135266304, 67637280, 33554432, 16908288, 8388608, 4194304, 2113665, 1048576, 528416, 264192, 131072, 65536, 32768, 16513, 8192, 4128, 2048, 1032, 516, 256, 129, 64, 32, 16, 8, 4, 2, 1]
# ['0x81020000', '0x40000000', '0x20000000', '0x10204081', '0x8100000', '0x4081020', '0x2000000', '0x1020000', '0x800000', '0x400000', '0x204081', '0x100000', '0x81020', '0x40800', '0x20000', '0x10000', '0x8000', '0x4081', '0x2000', '0x1020', '0x800', '0x408', '0x204', '0x100', '0x81', '0x40', '0x20', '0x10', '0x8', '0x4', '0x2', '0x1']

print("Testing Step 2 transformation")
b = 0x9d2c5680
s = 7

y = 0xdaedbeef
print("y = ", hex(y))

y1 = y ^ ((y << s) & b)
print("y1 = ", hex(y1))

yinv = matrixmult(Ainv_int, y1)
print("y1 inverse = ", hex(yinv))


# Now construct the matrix for Step 1
# B(11,0), B(12,1), ...B(31,??) should be set to 1
B = galois.GF2.Identity(32)

j = 0
for i in range(11, 32):
    B[i][j] = 1
    j = j + 1
B_int = []
for line in B.tolist():
    linestr = [str(x) for x in line]
    B_int.append(int("".join(linestr),2))
print("Matrix for Step 1:")
print(B_int)

# Compute the inverse matrix for Step 1
Binv = np.linalg.inv(B)
Binv_l = Binv.tolist()
Binv_int = []
for line in Binv_l:
    linestr = [str(x) for x in line]
    Binv_int.append(int("".join(linestr),2))
print("Inverse matrix for Step 1:")
print(Binv_int)


# Binv_int = [2147483648, 1073741824, 536870912, 268435456, 134217728, 67108864, 33554432, 16777216, 8388608, 4194304, 2097152, 2148532224, 1074266112, 537133056, 268566528, 134283264, 67141632, 33570816, 16785408, 8392704, 4196352, 2098176, 2148532736, 1074266368, 537133184, 268566592, 134283296, 67141648, 33570824, 16785412, 8392706, 4196353]




print("Testing Step 1 transformation")

u = 11
d = 0xffffffff

x_ = 0xabcd1234
y = x_ ^ ((x_ >> u) & d)

print("x_ = ", hex(x_))
print("y  = ", hex(y))

print("Testing matrix transformation")
y1 = matrixmult(B_int, x_)
print("y from matrixmult = ", hex(y1))
yinv = matrixmult(Binv_int, y)
print("inverse y from matrixmult = ", hex(yinv))


print("Test T and Tinv")
testvectors = [0x1234abcd, 0xdeadbeef, 0x55555555, 0xaaaaaaaa]
for v in testvectors:
    print("v = ", hex(v))
    z = T(v)
    print("T(v) = ", hex(z))
    x = Tinverse(z)
    print("Tinv(T(v)) = ", hex(x))
