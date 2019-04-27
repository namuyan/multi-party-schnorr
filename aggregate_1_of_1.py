import multi_party_schnorr


msg = b"nice meet"
eph = multi_party_schnorr.PyEphemeralKey()  # 18mS
pk = eph.keypair.get_public_key()
print("key:", pk.hex())
R, sig = eph.get_single_sign(msg)  # 19ms
print("R:", R.hex())
print("sig:", sig.hex())
result = multi_party_schnorr.verify_aggregate_sign(sig, R, pk, msg)  # 35ms
print("res:", result)
print("verify auto?", multi_party_schnorr.verify_auto(sig, R, pk, msg))
# from timeit import timeit
# timeit("single()", globals=globals(), number=10)
# check = lambda x: timeit(x, globals=globals(), number=10)*1000//10
