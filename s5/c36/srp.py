# To simulate this on the python command prompt, run:
# from srp import *
# and follow the instructions
import random
import hashlib
import hmac

# Define a NIST prime P-192 = 2**192 - 2**64 - 1
N = 6277101735386680763835789423207666416083908700390324961279
k = 3
g = 2
password = "SuP3rS3cr37P@ssW0rd"
salt = "saltsalt"

print("Begin by running client1()")

def client1():
    # generates DH exponent: a
    a = random.randrange(N)
    A = pow(g, a, N)
    print("client generates DH exponent: a = {}".format(a))
    print("client sends over to server: A = {}".format(A))
    print("*** Next step, call server1(A)")
    print()
    
def server1(A):
    # generates DH exponent: b
    b = random.randrange(N)
    x = int(hashlib.sha256((salt+password).encode()).hexdigest(),16)
    v = pow(g, x, N)
    B = (k*v + pow(g, b, N)) % N
    print("server generates DH exponent: b = {}".format(b))
    print("server generates: v = {}".format(v))
    print("server sends over to client: B = {}".format(B))
    print("server sends over to client: salt = {}".format(salt))
    print("*** Next step, call client2(A, B, a, salt)")
    print()

def client2(A, B, a, salt):
    u = int(hashlib.sha256((hex(A)[2:] + hex(B)[2:]).encode()).hexdigest(),16)
    x = int(hashlib.sha256((salt+password).encode()).hexdigest(),16)
    S = pow(B - k*pow(g,x,N), a+u*x, N)
    K = hashlib.sha256(hex(S)[2:].encode()).hexdigest()
    response = hmac.digest(K.encode(), salt.encode(), 'sha256')
    print("client sends over to server: response = {}".format(response))
    print("*** Next step, call server2(response, A, B, v, b)")
    print()

def server2(response, A, B, v, b):
    u = int(hashlib.sha256((hex(A)[2:] + hex(B)[2:]).encode()).hexdigest(),16)
    S = pow(A * pow(v, u, N), b, N)
    K = hashlib.sha256(hex(S)[2:].encode()).hexdigest()
    msgauth = hmac.digest(K.encode(), salt.encode(), 'sha256')
    print("server generates MAC = {}".format(msgauth))
    if (msgauth == response):
        print("Authenticated!")
    print()
