from multi_party_schnorr import PyKeyPair, verify_aggregate_sign, verify_auto
from time import time

s = time()
msg = b"nice meet"
keypair = PyKeyPair()  # 18mS
print(round((time()-s)*1000), "mSec")
pk = keypair.get_public_key()
print(round((time()-s)*1000), "mSec")
print("key:", pk.hex())
R, sig = keypair.get_single_sign(msg)  # 19ms
print(round((time()-s)*1000), "mSec")
print("R:", R.hex())
print("sig:", sig.hex())
result = verify_aggregate_sign(sig, R, pk, msg)  # 35ms
print(round((time()-s)*1000), "mSec")
print("res:", result)
print("verify auto?", verify_auto(sig, R, pk, msg))
print(round((time()-s)*1000), "mSec")

