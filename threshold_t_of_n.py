import multi_party_schnorr
from time import time

start = time()
t = 2  # threshold
n = 5  # signers
m = 4  # signed
pair0 = multi_party_schnorr.PyThresholdKey.generate(t, n)
pair1 = multi_party_schnorr.PyThresholdKey.generate(t, n)
pair2 = multi_party_schnorr.PyThresholdKey.generate(t, n)
pair3 = multi_party_schnorr.PyThresholdKey.generate(t, n)
pair4 = multi_party_schnorr.PyThresholdKey.generate(t, n)

vss0, sec0 = pair0.get_variable_secret_sharing()
vss1, sec1 = pair1.get_variable_secret_sharing()
vss2, sec2 = pair2.get_variable_secret_sharing()
vss3, sec3 = pair3.get_variable_secret_sharing()
vss4, sec4 = pair4.get_variable_secret_sharing()

signers = [x.keypair.get_public_key() for x in (pair0, pair1, pair2, pair3, pair4)]
vss_points = [vss0, vss1, vss2, vss3, vss4]
scalars = [sec0, sec1, sec2, sec3, sec4]

share0 = pair0.keygen_t_n_parties(signers, vss_points, scalars)
share1 = pair1.keygen_t_n_parties(signers, vss_points, scalars)
share2 = pair2.keygen_t_n_parties(signers, vss_points, scalars)
share3 = pair3.keygen_t_n_parties(signers, vss_points, scalars)
share4 = pair4.keygen_t_n_parties(signers, vss_points, scalars)
Y = multi_party_schnorr.summarize_public_points(signers)
print("Y", Y.hex())
print("share0", share0.hex())
print("share1", share1.hex())
print("share2", share2.hex())
print("share3", share3.hex())
print("share4", share4.hex())
print("finish", round(time() - start, 3), "Sec")

parties_index = [0, 1, 2, 3]
eph0 = multi_party_schnorr.PyThresholdKey.generate(t, m, parties_index)
eph1 = multi_party_schnorr.PyThresholdKey.generate(t, m, parties_index)
eph2 = multi_party_schnorr.PyThresholdKey.generate(t, m, parties_index)
eph3 = multi_party_schnorr.PyThresholdKey.generate(t, m, parties_index)

eph_vss0, eph_sec0 = eph0.get_variable_secret_sharing()
eph_vss1, eph_sec1 = eph1.get_variable_secret_sharing()
eph_vss2, eph_sec2 = eph2.get_variable_secret_sharing()
eph_vss3, eph_sec3 = eph3.get_variable_secret_sharing()

eph_signers = [x.keypair.get_public_key() for x in (eph0, eph1, eph2, eph3)]
eph_vss_points = [eph_vss0, eph_vss1, eph_vss2, eph_vss3]
eph_scalars = [eph_sec0, eph_sec1, eph_sec2, eph_sec3]

eph_share0 = eph0.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share1 = eph1.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share2 = eph2.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
eph_share3 = eph3.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars)
V = multi_party_schnorr.summarize_public_points(eph_signers)
print("V", V.hex(), eph0.my_index, eph1.my_index, eph2.my_index)
print("eph share0", eph_share0.hex())
print("eph share1", eph_share1.hex())
print("eph share2", eph_share2.hex())
print("eph share3", eph_share3.hex())
print("finish", round(time() - start, 3), "Sec")

msg = b"hello nice sharing"
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
print("parties_index", parties_index)
sigma = multi_party_schnorr.summarize_local_signature(t, n, m, e0, gammas, parties_index, vss_points, eph_vss_points)
print("finish", round(time() - start, 3), "Sec")
print("sigma", sigma.hex())

sign_start = time()
r = multi_party_schnorr.verify_threshold_sign(sigma, Y, V, msg)
print("verify?", r, round((time()-sign_start)*1000), "mSec")
print("finish", round(time() - start, 3), "Sec")
print("verify auto?", multi_party_schnorr.verify_auto(sigma, V, Y, msg))
