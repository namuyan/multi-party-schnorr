import multi_party_schnorr


msg = b"nice meet"
pair = multi_party_schnorr.PyKeyPair()  # 18ms
eph = multi_party_schnorr.PyEphemeralKey.from_keypair(pair)  # 5uS
R, sig = eph.get_single_sign(msg)  # 18ms
result = multi_party_schnorr.verify_aggregate_sign(sig, R, pair.get_public_key(), msg, False)  # 35ms

# from timeit import timeit
# timeit("single()", globals=globals(), number=10)
