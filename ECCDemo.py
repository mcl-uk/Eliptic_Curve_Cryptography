#  Elliptic Curve Cryptography in python from scratch
#  -------------------------------------------------
#  SJM / MCL Oct 2024

# Inspired by: https://www.johannes-bauer.com/compsci/ecc/

# Demo of 192bit ECC keygen, encrypt & decrypt in basic python
# *** Currently this code does not run correctly in microPython ***

import os # for urandom numbers
from hashlib import md5

# By convention lower-case variables are integers, uppercase ones are (xy) points
# Gobal curve paramters (public) as per brainpoolP192t1 from openSSL
p  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297 # prime modulus
a  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86294 # curve a parameter
b  = 0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79 # curve b parameter, strangely not used
G  = [0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129, 0x097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9]
n  = 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1 # 'order' of G

# --- support functions ---------------------------------------------------------------

# An intermediate operation required by add() below
def inv(P):
    [xP, yP] = P
    if xP == None: return [None, None]
    return [xP, -yP % p]

# An intermediate operation required by mul() below
def dbl(P):
    if P[0] == None: return P
    if P[1] == 0: return [None, None]
    [xP, yP] = P
    s = (3*pow(xP,2,p)+a) * pow(2*yP, -1, p)
    xR = (pow(s,2,p) - 2*xP) % p
    return [ xR, (-yP + s*(xP-xR)) % p ]

# An intermediate operation required by mul() below
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

# This mul() operation is the heart and soul of ECC crypto.
# Here we 'multiply' point P, an xy point on the curve, by integer k within our
# finite number field. Think of it as moving along the curve by a distance k.
# The returned value is some other point on the curve, k clicks from P.
def mul(P, k):
    if P[0] == None: return P
    N, R = P, [None, None]
    while k: # bit-wise itteration over k
        bit = k % 2
        k >>= 1
        if bit: R = add(R, N)
        N = dbl(N)
    return R

# microPython does not support int.bit_length()
def bitLen(n):
    return len(bin(n).strip('0b'))

def bytLen(n):
    return (len(hex(n).strip('0x'))+1)//2


# --- MAIN -----------------------------------------------------------------------

# Before we start, let's just check our numbers and make sure that G actually
# is a valid point on the curve...
x,y = G
assert pow(y, 2, p) == (pow(x, 3, p) + ((a * x) % p) + b) % p
# Note that Python's pow() function can handle integers of arbitrary length and
# supports an optional third modulus argument.
# If this assertion fails check that you removed the leading 04 byte from G

print(f"ECC demo using {bitLen(n)} bit key\n")

# Bob's private/public key-pair generation:
# The private key, da, is just a random number 0 < da < n
# ie up to 57 decimal digits for a 192bit n
da = 12345678901234567890123456789012345678901234567890123456
assert da < n
# Public key is just an xy point on the curve derived from da
Qa = mul(G, da)  # (1) public key
# So, from our starting point G we've moved a random distance da along the curve
# and arrived at point Qa. Note that despite the fact that G and Qa are both made
# public, provided the numbers involved are large enough, it's not feasible to back-
# calculate da.
print(f"Bob's Public key: {'/'.join(str(x) for x in Qa)}")
print()

# Alice...
# 'encryption' or more accurately shared secret creation and conversion for transmission
# First, get a random number 0 < rnd < n to seed the operation
rnd = int.from_bytes(os.urandom(bytLen(n)), 'big') # urandom requres a byte-count
while rnd > n: rnd >>= 1 # ensure our rnd is < n
S = mul(Qa, rnd)  # (2) S is the secret xy point to be cryptographically shared
# Create our secret AES key from S, for example take its md5 hash
s = md5(str(S).encode()).digest() # byte string
print(f"Alice's secret:   {s.hex()}")
R = mul(G, rnd)   # (3) our 'cypherText' - another xy point on the curve

# In bandwidth constrained applications we can 'compress' R by abreviating it
# to its X co-ordinate and the 'sign' of its Y co-ord for transmission.
# Upon reception, Bob must recalculate Y given X, remember the LHS of the
# curve equation is Y^2 so solving for Y yields two results, one +ve, one -ve.
# Taking a square root in finite field maths is tricky but IF p mod 4 == 3
# there's a shortcut: sqrt(v) = +/- pow(v, (p+1)//4, p).
# For illustration lets compress for transmission and decompress at reception.
#
assert p%4 == 3
cR = R[0]*2 + (0,1)[R[1] > p//2] # compress
cR_rx = cR # transmit
print(f"CypherText:       {hex(cR).strip('0x')}")

# Bob...
# receive & decompress...
rx = cR_rx // 2
rysign = cR_rx % 2
rysqd = (pow(rx, 3, p) + a*rx + b) % p
ry = pow(rysqd, (p+1)//4, p) # gives sqrt(ysqd) !
if (rysign == 1) != (ry > p//2): ry = -ry%p
Rrx = [rx, ry] # the decompressed point

# 'decryption'
Srx = mul(Rrx, da)  # (4) re-create the shared secret xy point S - wow that was easy!
assert Srx == S

# This works because (see mul() above), in ECC world:
# If G.da (1) takes you to point Qa and Qa.r (2) takes you on to point S, then similarly
# G.r (3) takes you to point R and R.da (4) takes you to [Ta-Da!] S.
#   G -------------da-----------> Qa -----r-----> S
#   G -----r-----> R  -------------da-----------> S
# Both Alice and Bob have moved the same distance along the curve and arrived at
# the same point because [r + da] == [da + r]. Same journey, different way-points.
# In ECC it's easy to find a destination point given a starting point and a distance but
# very dificult to find the distance between two arbitrary points, this is the source of
# the asymetry and why it all works. It is both amazing and great!

# Now re-create Alice's secret AES key
srx = md5(str(Srx).encode()).digest() # byte string
assert srx == s
print(f'Recovered secret: {srx.hex()}')

# Both sides can now use s (=srx) as the key for subsequent AES comms
