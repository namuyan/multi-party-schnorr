import multi_party_schnorr
from time import time

start = time()
pair0 = multi_party_schnorr.PyKeyPair()  # 27mS
pair1 = multi_party_schnorr.PyKeyPair()
pair2 = multi_party_schnorr.PyKeyPair()
print("create 3 pairs", pair0, pair1, pair2)
signers = [x.get_public_key() for x in (pair0, pair1, pair2)]
eph0 = multi_party_schnorr.PyEphemeralKey()  # 19.5mS
eph1 = multi_party_schnorr.PyEphemeralKey()
eph2 = multi_party_schnorr.PyEphemeralKey()
print("create 3 ephemeral", eph0, eph1, eph2)
ephemeral = [x.keypair.get_public_key() for x in (eph0, eph1, eph2)]
agg0 = multi_party_schnorr.PyAggregate.generate(signers, ephemeral, pair0, eph0)  # 53mS
agg1 = multi_party_schnorr.PyAggregate.generate(signers, ephemeral, pair1, eph1)
agg2 = multi_party_schnorr.PyAggregate.generate(signers, ephemeral, pair2, eph2)
print("create 3 aggregates {} {} {}".format(agg0, agg1, agg2))
msg = b"hello world"
sig0 = agg0.get_partial_sign(msg)  # 0.021mS
sig1 = agg1.get_partial_sign(msg)
sig2 = agg2.get_partial_sign(msg)
sig01 = agg0.add_signature_parts(sig0, sig1)  # 0.011mS
sig012 = agg0.add_signature_parts(sig01, sig2)
R = agg0.R()  # 0.0025mS
apk = agg0.apk()  # 0.0011mS
print("sig", sig012.hex())
print("apk:", apk.hex())
print("R:", R.hex())
res = multi_party_schnorr.verify_aggregate_sign(sig012, R, apk, msg)  # 35.5mS
print("result:", res)
print("verify auto?", multi_party_schnorr.verify_auto(sig012, R, apk, msg))
print(int((time() - start, 4) * 1000), "mS")
