from static_params import keys, vss, sec, Y
from static_params import eph_keys, eph_vss, eph_sec, V
import multi_party_schnorr
from binascii import a2b_hex
from time import time

start = time()
t = 2  # threshold
n = 5  # signers
m = 4  # signed
pair0 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, n, a2b_hex(keys[0]))
pair1 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, n, a2b_hex(keys[1]))
pair2 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, n, a2b_hex(keys[2]))
pair3 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, n, a2b_hex(keys[3]))
pair4 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, n, a2b_hex(keys[4]))

vss0, sec0 = [a2b_hex(x) for x in vss[0]], [a2b_hex(s) for s in sec[0]]
vss1, sec1 = [a2b_hex(x) for x in vss[1]], [a2b_hex(s) for s in sec[1]]
vss2, sec2 = [a2b_hex(x) for x in vss[2]], [a2b_hex(s) for s in sec[2]]
vss3, sec3 = [a2b_hex(x) for x in vss[3]], [a2b_hex(s) for s in sec[3]]
vss4, sec4 = [a2b_hex(x) for x in vss[4]], [a2b_hex(s) for s in sec[4]]

signers = [x.keypair.get_public_key() for x in (pair0, pair1, pair2, pair3, pair4)]
vss_points = [vss0, vss1, vss2, vss3, vss4]
scalars = [sec0, sec1, sec2, sec3, sec4]

share0 = pair0.keygen_t_n_parties(signers, vss_points, scalars)
share1 = pair1.keygen_t_n_parties(signers, vss_points, scalars)
share2 = pair2.keygen_t_n_parties(signers, vss_points, scalars)
share3 = pair3.keygen_t_n_parties(signers, vss_points, scalars)
share4 = pair4.keygen_t_n_parties(signers, vss_points, scalars)
_Y = multi_party_schnorr.summarize_public_points(signers)
Y = a2b_hex(Y)
assert Y == _Y
print("Y", Y.hex(), pair0.my_index, pair1.my_index, pair2.my_index, pair3.my_index, pair4.my_index)
print("share0", share0.hex())
print("share1", share1.hex())
print("share2", share2.hex())
print("share3", share3.hex())
print("share4", share4.hex())
print("finish", round(time() - start, 3), "Sec")

eph0 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, m, a2b_hex(eph_keys[0]))
eph1 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, m, a2b_hex(eph_keys[1]))
eph2 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, m, a2b_hex(eph_keys[2]))
eph3 = multi_party_schnorr.PyThresholdKey.from_secret_key(t, m, a2b_hex(eph_keys[3]))

eph_vss0, eph_sec0 = [a2b_hex(x) for x in eph_vss[0]], [a2b_hex(s) for s in eph_sec[0]]
eph_vss1, eph_sec1 = [a2b_hex(x) for x in eph_vss[1]], [a2b_hex(s) for s in eph_sec[1]]
eph_vss2, eph_sec2 = [a2b_hex(x) for x in eph_vss[2]], [a2b_hex(s) for s in eph_sec[2]]
eph_vss3, eph_sec3 = [a2b_hex(x) for x in eph_vss[3]], [a2b_hex(s) for s in eph_sec[3]]

eph_signers = [x.keypair.get_public_key() for x in (eph0, eph1, eph2, eph3)]
eph_vss_points = [eph_vss0, eph_vss1, eph_vss2, eph_vss3]
eph_scalars = [eph_sec0, eph_sec1, eph_sec2, eph_sec3]

eph_share0 = eph0.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share1 = eph1.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share2 = eph2.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share3 = eph3.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
_V = multi_party_schnorr.summarize_public_points(eph_signers)
V = a2b_hex(V)
assert _V == V

print("V", V.hex(), eph0.my_index, eph1.my_index, eph2.my_index)
print("eph share0", eph_share0.hex())
print("eph share1", eph_share1.hex())
print("eph share2", eph_share2.hex())
print("eph share3", eph_share3.hex())
print("finish", round(time() - start, 3), "Sec")

msg = bytes([79, 77, 69, 82])
e0, gamma0 = multi_party_schnorr.get_local_signature(share0, eph_share0, Y, V, msg)
e1, gamma1 = multi_party_schnorr.get_local_signature(share1, eph_share1, Y, V, msg)
e2, gamma2 = multi_party_schnorr.get_local_signature(share2, eph_share2, Y, V, msg)
e3, gamma3 = multi_party_schnorr.get_local_signature(share3, eph_share3, Y, V, msg)
assert e0 == e1 == e2 == e3
print("e", e0.hex())
print("gamma0", gamma0.hex())
print("gamma1", gamma1.hex())
print("gamma2", gamma2.hex())
print("gamma3", gamma3.hex())

gammas = [gamma0, gamma1, gamma2, gamma3]
parties_index = [x.my_index for x in (pair0, pair1, pair2, pair3)]
print("parties_index", parties_index)
sigma = multi_party_schnorr.summarize_local_signature(t, n, m, e0, gammas, parties_index, vss_points, eph_vss_points)
print("sigma", sigma.hex())
print("finish", round(time() - start, 3), "Sec")

sign_start = time()
r = multi_party_schnorr.verify_threshold_sign(sigma, Y, V, msg)
print("verify?", r, round(time()-sign_start, 3), "Sec")
print("finish", round(time() - start, 3), "Sec")
