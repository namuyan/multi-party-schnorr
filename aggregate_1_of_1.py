import multi_party_schnorr


msg = b"nice meet"
eph = multi_party_schnorr.PyEphemeralKey()  # 5uS
print("key:", eph.keypair.get_public_key().hex())
R, sig = eph.get_single_sign(msg)  # 18ms
print("R:", R.hex())
print("sig:", sig.hex())
result = multi_party_schnorr.verify_aggregate_sign(sig, R, eph.keypair.get_public_key(), msg)  # 35ms
print("res:", result)
# from timeit import timeit
# timeit("single()", globals=globals(), number=10)
