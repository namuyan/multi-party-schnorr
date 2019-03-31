import multi_party_schnorr

pair0 = multi_party_schnorr.PyKeyPair()
pair1 = multi_party_schnorr.PyKeyPair()
pair2 = multi_party_schnorr.PyKeyPair()
print("create 3 pairs", pair0, pair1, pair2)
signers = [x.get_public_key() for x in (pair0, pair1, pair2)]
eph0 = multi_party_schnorr.PyEphemeralKey()
eph1 = multi_party_schnorr.PyEphemeralKey()
eph2 = multi_party_schnorr.PyEphemeralKey()
print("create 3 ephemeral", eph0, eph1, eph2)
ephemeris = [x.keypair.get_public_key() for x in (eph0, eph1, eph2)]
agg0 = multi_party_schnorr.PyAggregate.generate(signers, ephemeris, pair0, eph0)
agg1 = multi_party_schnorr.PyAggregate.generate(signers, ephemeris, pair1, eph1)
agg2 = multi_party_schnorr.PyAggregate.generate(signers, ephemeris, pair2, eph2)
print("create 3 aggregates {} {} {}".format(agg0, agg1, agg2))
msg = b"hello world"
sig0 = agg0.get_partial_sign(msg)
sig1 = agg1.get_partial_sign(msg)
sig2 = agg2.get_partial_sign(msg)
_, sig01 = agg0.add_signature_parts(sig0, sig1)
_, sig012 = agg0.add_signature_parts(sig01, sig2)
R = agg0.R()
apk = agg0.apk()
print("sig", sig012.hex())
print("apk:", apk.hex())
print("R:", R.hex())
res = multi_party_schnorr.verify_aggregate_sign(sig012, R, apk, msg, True)
print("result:", res)
