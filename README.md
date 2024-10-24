# Eliptic_Curve_Cryptography
<i>ECC explained and illustrated with simple python code</i>

Inspired by https://www.johannes-bauer.com/compsci/ecc/ and https://github.com/user8547/fast-ecc-python

Demo of ECC keygen, encrypt & decrypt in plain python, migrateable to microPython

First, note there is nothing eliptical or curvey about 'eliptic curves' in this context.
Because it exists in a finite number space the 'curve' is in fact a collection of xy points that satisfy the cubic equation: y^2 = x^3 + ax + b _within_ our chosen number space.
Imagine a (huge) piece of graph paper with many dots peppered on it.
One of dots is used as a starting point (referred to as G) and the maths of ECC involves moving through the dots on a well defined but seemingly random route.

Perhaps surprisingly the computational demands of ECC are significantly less than those of RSA, particularly in key generation.
Plus ECC key-lengths can be much smaller for the same level of security.
This would seem to make ECC an attractive option for micro-controller based applications and indeed the code presented here is easily mirateable to micropython.

ECC is a public-key (asymetric) cryptosystem suited to establishing a shared secret crypto key for use in subsequent (symetrically) secured communications, eg AES.
Unlike RSA it is not suited to encrypting/decrypting arbitrary messages, in ECC there is no plain-text as such.
Instead a random, secret, xy point on the curve is identified and cryptographically shared.
A key for subsequent (AES) communications is derived from the shared secret xy point by some mutally agreed algorithm.

So if Alice wants to set up a secure channel to Bob (using some symetric encryption scheme) she'll need to somehow share a secret key with him.
As with any public key system Bob must have already prepared a key-set and published his public key.
In ECC he must also have chosen a particular eliptic curve with which to work and published that choice too.

Meanwhile Alice must generate a one-time random number and use Bob's public key to derive two related xy points on his chosen curve.
One becomes the shared secret, the other is sent on to Bob over the open channel.
When Bob receives Alice's xy point he can use his private key to obtain a copy of Alice's secret.
For Eve, the evesdropper, there is no realistic way obtain Alice's secret without access to Bob's private key.

The python code presented is a working illustration of both the key generation process and secret sharing mechanism.
Use at your own risk and not in any production environment.
