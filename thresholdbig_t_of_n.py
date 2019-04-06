from multi_party_schnorr import PyThresholdKey, summarize_public_points, \
    get_local_signature, summarize_local_signature, verify_threshold_sign
from time import time
from random import shuffle

start = time()
t = 2  # threshold
n = 5  # signers
m = 4  # signed
pair_list = list()
for _ in range(n):
    pair_list.append(PyThresholdKey.generate(t, n))

vss_points = list()
scalars = list()
for p in pair_list:
    vss, sec = p.get_variable_secret_sharing()
    vss_points.append(vss)
    scalars.append(sec)

signers = [x.keypair.get_public_key() for x in pair_list]

share_list = list()
for p in pair_list:
    share_list.append(p.keygen_t_n_parties(signers, vss_points, scalars))

Y = summarize_public_points(signers)
print("Y", Y.hex())
for i, s in enumerate(share_list):
    print("share", i, s.hex())

print("finish", round(time() - start, 3), "Sec")

all_parties = list(range(n))
shuffle(all_parties)
parties_index = list()
for _ in range(m):
    parties_index.append(all_parties.pop())
print("parties_index", parties_index)

eph_list = list()
for _ in range(m):
    k = PyThresholdKey.generate(t, m, parties_index)
    eph_list.append(k)

eph_vss_points = list()
eph_scalars = list()
for e in eph_list:
    vss, sec = e.get_variable_secret_sharing()
    eph_vss_points.append(vss)
    eph_scalars.append(sec)

eph_signers = [x.keypair.get_public_key() for x in eph_list]

eph_share_list = list()
for e in eph_list:
    eph_share_list.append(e.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars))

V = summarize_public_points(eph_signers)
print("V", V.hex())
for i, s in enumerate(eph_share_list):
    print("eph_share", i, s.hex())

print("finish", round(time() - start, 3), "Sec")

msg = b"hello nice sharing"
e = b''
gamma_list = list()
for i, position in enumerate(parties_index):
    e, g = get_local_signature(share_list[position], eph_share_list[i], Y, V, msg)
    print("gamma", i, position, g.hex())
    gamma_list.append(g)
print("e", e.hex())

sigma = summarize_local_signature(t, n, m, e, gamma_list, parties_index, vss_points, eph_vss_points)
print("finish", round(time() - start, 3), "Sec")
print("sigma", sigma.hex())

sign_start = time()
r = verify_threshold_sign(sigma, Y, V, msg)
print("verify?", r, round((time()-sign_start)*1000), "mSec")
print("finish", round(time() - start, 3), "Sec")
