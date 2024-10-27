# Elliptic Curve Cryptography
<i>ECC explained and illustrated with simple python code</i>

Inspired by https://www.johannes-bauer.com/compsci/ecc/ and https://github.com/user8547/fast-ecc-python

Demo of ECC keygen and key establishment in plain python, also runs on microPython

First, note there is nothing elliptical or curvey about 'eliptic curves' in this context.
In ECC the curve is constrained to a finite integer number space, or field, and becomes a collection of xy points that satisfy the equation: y^2 = x^3 + ax + b _within_ our chosen number space.
Imagine a (huge) piece of graph paper with many dots peppered on it.
One of the dots is chosen as a starting point (referred to as G) and the maths of ECC involves moving through the dots on a well defined but seemingly random route.
Oh and when I say huge, think of something like <a href=https://www.johannes-bauer.com/compsci/ecc/sageplot_06.png>this</a> but on a scale the size of the galaxy :-)

Perhaps surprisingly the computational demands of ECC can be less than those of other PKC systems as ECC key-lengths can be much shorter for the same level of security.
For example an ECC key length of 256bits is roughly equivalent to a 3072bit RSA key. 
This would seem to make ECC an attractive option for micro-controller based applications and indeed the code presented here works with microPython.
When I ran this demo on an ESP32 WROOM-32E in microPython 1.23 with timing analysis: keygen took ~100ms, encryption took ~300ms and de-cryption ~100ms.
Encryption takes longer because it requires 2 mul() operations plus a random number generation.

ECC is a public-key (asymetric) cryptosystem suited to establishing a shared secret crypto key (key establishment) for use in subsequent (symetrically) secured communications, eg AES.
It also has applications in digital signing but that's another story.
Unlike RSA it is not suited to encrypting/decrypting arbitrary messages, in ECC there is no plain-text as such.
Instead a random, secret, xy point on the curve is identified and cryptographically shared.
A key for subsequent (AES) communications is derived from the shared secret xy point by some mutually agreed algorithm.

So if Alice wants to set up a secure channel to Bob (using some symetric encryption scheme) she'll need to somehow share a secret key with him.
ECC provides a mechanism for this but, as with any public key system, Bob must have already prepared a key-pair and published a public key.
In ECC he must also have chosen a particular eliptic curve with which to work and published that choice too.

Meanwhile Alice must generate a one-time random number and use Bob's public key to derive two related xy points on his chosen curve.
One becomes the shared secret, the other is sent on to Bob over the open channel.
When Bob receives Alice's xy point he can use his private key to obtain a copy of Alice's secret.
For Eve, the evesdropper, there is no realistic way to obtain Alice's secret without access to Bob's private key.
See the comments in the python code for more details.

A particular eliptic curve is specified by parameters: p, a, b, G & n where:
<pre>
  p      is a large prime that sets the curve's number-space or modulus,
  a & b  are integers that define the curve,
  G      is the 'generation point', an xy starting point on the curve,
  n      is the order of G - it sets the upper bound for Alice & Bob's random numbers.
</pre>
Bob's public key, Qa, is some other xy point on the curve.

There are an infinite number of possible elliptic curves, some better suited than others to crypto.
Choosing a curve suitable for crypto is a very technical process so it's best to find an already engineered curve off-the-shelf.
We can use openSSL to help here, first ask openSSL for a list of all it's known elliptic curves with cmd:

<code>$ openssl ecparam -list_curves</code>

Get the parameters for one of them (eg the brainpoolP192t1) using cmd:

<code>$ openssl ecparam -param_enc explicit -text -noout -no_seed -name brainpoolP192t1</code>

This yields all the info required to define a particular elliptic curve together with a generation point, ie: p,a,b,G & n.
In the case of the generation point G, remove the initial 04 byte header then separate out the x & y components - first half x, second half y.
We'll be using this brainpoolP192t1 curve for our demo.

The python code presented is a working illustration of both the key generation process and secret sharing mechanism.
Please refer to the comments within the code for more detail.
Use at your own risk and not in any kind of production environment!


