from fastecdsa.keys import gen_keypair
from fastecdsa.curve import secp256k1
from fastecdsa.ecdsa import sign, verify
from time import time

s = time()
sec, pub = gen_keypair(secp256k1)
print(round((time()-s)*1000), "mSec")
sig = sign(b'hello world', sec, secp256k1)
print(round((time()-s)*1000), "mSec")
verify(sig, b'hello world', pub, secp256k1)
print(round((time()-s)*1000), "mSec")
