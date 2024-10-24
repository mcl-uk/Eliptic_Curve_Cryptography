#
#  Eliptic Curve Cryptography in python from scratch
#  -------------------------------------------------
#
# Inspired by: https://www.johannes-bauer.com/compsci/ecc/
#
# Demo of ECC keygen, encrypt & decrypt in plain python, migrateable to microPython
#
# First, note there is nothing eliptical or curvey about 'eliptic curves' in this
# context. Because it exists in a finite number space the 'curve' is in fact a
# collection of xy points that satisfy the cubic equation: y^2 = x^3 + ax + b
# _within_ our chosen number space. Imagine a (huge) piece of graph paper with
# many dots peppered on it. One of dots is used as a starting point (referred to
# as G) and the maths of ECC involves moving through the dots on a well defined
# but seemingly random route.
#
# The computational demands of ECC are significantly less than those of RSA,
# particularly for the process of key generation. Plus ECC key-lengths can be much
# smaller for the same level of security. This makes ECC attractive for micro-
# controller based applications.
#
# ECC is a public-key (asymetric) cryptosystem suited to establishing a shared secret
# crypto key for use in subsequent (symetrically) secured communications, eg AES.
# Unlike RSA it is not suited to encrypting/decrypting arbitrary messages, in ECC
# there is no plain-text as such. Instead a random, secret, xy point is identified
# and cryptographically shared. A key for subsequent (AES) communications is derived
# from the shared secret xy point by some mutally agreed algorithm.
#
# So if Alice wants to set up a secure channel to Bob (using some symetric
# encryption scheme) she'll need to somehow share a secret key with him.
# As with any public key system Bob must have already prepared a key-set and
# published his public key. In ECC he must also have chosen a particular eliptic
# curve with which to operate and published that choice too.
#
# Meanwhile Alice must generate a one-time random number and use Bob's key-set
# to derive two related xy points on his chosen eliptic curve - one becomes the
# shared secret, the other is sent to Bob over the open channel.
# When Bob receives Alice's xy point he can use his private key to obtain a copy
# of Alice's secret. Eve, the evesdropper, cannot decrypt the message without
# access to Bob's private key.
#
# The public key-set comprises the chosen curve specified by parameters:
# p, a, b, G & n plus Bob's public key Qa where:
#  p is a large prime that defines the curve's number-space or modulus,
#  a & b are integers that further define the curve,
#  G is the 'generation point', an xy starting point on the curve,
#  n is the order of G - it sets the upper bound for Alice & Bob's random numbers.
# Bob's public key, Qa, is another xy point on the curve.
#
# There are an infinite number of possible eliptic curves, some suited better than
# others for crypto. So its best to find an already engineered curve off-the-shelf.
# We can use openSSL to help here...
# First ask openSSL for a list of all it's known eliptic curves with cmd:
#  $ openssl ecparam -list_curves
# Get the parameters for one of them (eg the brainpoolP192t1) using cmd:
#  $ openssl ecparam -param_enc explicit -text -noout -no_seed -name brainpoolP192t1
# This yields all the info required to define a curve together with a generation point,
# ie: p,a,b,G & n.  In the case of the generation point G remove the initial 04 byte
# header then separate out the x & y components - first half x, second half y
# We'll be using this brainpoolP192t1 curve for our demo.

import os # for urandom numbers
from hashlib import md5

# By convention lower-case variables are integers, uppercase ones are (xy) points
# Gobal curve paramters (public) as per brainpoolP192t1
p  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297 # prime modulus
a  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86294 # curve a parameter
b  = 0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79 # curve b parameter, strangely not used
G  = [0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129, 0x097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9]
n  = 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1 # 'order' of G

# --- support functions from https://github.com/user8547/fast-ecc-python ---

def inv(P):
    [xP, yP] = P
    if xP == None: return [None, None]
    return [xP, -yP % p]

def add(P,Q):
    if P == Q: return dbl(P)
    if P[0] == None: return Q
    if Q[0] == None: return P
    if Q == inv(P): return [None, None]
    [xP, yP] = P
    [xQ, yQ] = Q
    s = (yP - yQ) * pow(xP-xQ, -1, p)
    xR = (pow(s,2,p) - xP -xQ) % p
    return [ xR, (-yP + s*(xP-xR)) % p ]

def dbl(P):
    if P[0] == None: return P
    if P[1] == 0: return [None, None]
    [xP, yP] = P
    s = (3*pow(xP,2,p)+a) * pow(2*yP, -1, p)
    xR = (pow(s,2,p) - 2*xP) % p
    return [ xR, (-yP + s*(xP-xR)) % p ]

# Here we 'multiply' P, an xy point on the curve, by integer k within our
# finite number space. Think of it as moving along the curve by a distance k 
# This operation is the heart and soul of ECC crypto.
def mul(P, k):
    if P[0] == None: return P
    N, R = P, [None, None]
    while k:
        bit = k % 2
        k >>= 1
        if bit: R = add(R, N)
        N = dbl(N)
    return R

# --- MAIN -----------------------------------------------------------------------

print(f"ECC demo using {n.bit_length()} bit key\n")

# Bob's private/public key-pair generation:
# The private key, da, is just a random number 0 < da < n
# ie up to 57 decimal digits for a 192bit n
da = 12345678901234567890123456789012345678901234567890123456
assert da < n
# Public key is just an xy point on the curve derived from da
Qa = mul(G, da)  # (1) public key
print(f"Bob's Public key: {'/'.join(str(x) for x in Qa)}")
print()

# 'encryption' or more accurately secret-point / transmitted-point generation
# First, get a random number 0 < rnd < n to seed the operation
rnd = int.from_bytes(os.urandom(n.bit_length() - 1))
S = mul(Qa, rnd)  # (2) S is the secret xy point to be cryptographically shared
# Create our secret AES key from S, for example take its md5 hash
s = md5(str(S).encode()).digest() # byte string
print(f"Alice's secret:   {s.hex()}")

R = mul(G, rnd)   # (3) 'cypherText' an xy point on the curve
print(f"CypherText:       {'/'.join(str(x) for x in R)}")

# 'decryption'
Srx = mul(R, da) # (4) the shared secret xy point

# This works because, in ECC world:
# If G.da (1) takes you to point Qa and Qa.r (2) takes you on to point S, then similarly
# G.r (3) takes you to point R and R.da (4) takes you on to the same point S.
# Both Alice and Bob have essentially moved the same distance along the curve and arrived
# at the same point because [r + da] == [da + r]. The same journey, different way-points.
# In ECC it's easy to find a destination point given a starting point and a distance but
# very dificult to find the distance between two points, this is the source of the
# asymetry and why it all works.

# Now re-create Alice's secret AES key
srx = md5(str(Srx).encode()).digest() # byte string
print(f'Recovered secret: {srx.hex()}')
assert Srx == S
assert srx == s
# Both sides can now use s (=srx) as the key for subsequent AES comms

# --- FYI ---

# A Sage (https://cocalc.com/features/sage) illustration of keygen, 'encrypt' & 'decrypt'...
# In the lines below '*' is not a normal multiply (see mul() above)
# also by convention lower-case variables are integers, uppercase ones are (xy) points
# Fp = FiniteField(0x00c302f41d932a36cda7a3463093d18db78fce476de1a86297) # p, our mudulus
# C = EllipticCurve(Fp, [ 0x00c302f41d932a36cda7a3463093d18db78fce476de1a86294, 0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79 ]) # Fp,a,b
# print(hex(C.cardinality()))
#  -> c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1
# G = C.point((0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129, 0x097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9)) # (Gx,Gy)
# print(hex(G.order()))
#  -> c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1
#
# # GeyGen...
# da = 98798760876087087098595 # private key, just a random number 0<da<n
# Qa = da * G # Qa is our public key (in addition to public curve params p,a,b & G)
# # Generate a secret point to secretly share
# r = 9876897650850558765 # a random < n
# R = r * G  # R is the "cypherText"
# S = r * Qa # S is the shared secret
# print(S)
#  -> (1114636321152080090700161459824069947138473627825249766409 : 4086529875489135096725155509097443196244045899173204892732 : 1)
# # Send cypherText R
# # recover S from the secret key da & the received R
# Srx = da*R # private key * CypherText yields point S
# print(Srx)
#  -> (1114636321152080090700161459824069947138473627825249766409 : 4086529875489135096725155509097443196244045899173204892732 : 1)
# # Check Srx == S
