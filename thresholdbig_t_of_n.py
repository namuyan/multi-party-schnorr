from multi_party_schnorr import PyThresholdKey, summarize_public_points, \
    get_local_signature, summarize_local_signature, verify_threshold_sign
from time import time
from random import shuffle

start = time()
t = 2  # threshold
n = 8  # signers
m = 4  # signed
pair_list = list()
for _ in range(n):
    pair_list.append(PyThresholdKey.generate(t, n))

print("0..", round(time() - start, 3), "Sec")

vss_points = list()
scalars = list()
for p in pair_list:
    vss, sec = p.get_variable_secret_sharing()
    vss_points.append(vss)
    scalars.append(sec)

print("1..", round(time() - start, 3), "Sec")

signers = [x.keypair.get_public_key() for x in pair_list]

share_list = list()
for p in pair_list:
    share_list.append(p.keygen_t_n_parties(signers, vss_points, scalars))

print("2..", round(time() - start, 3), "Sec")

Y = summarize_public_points(signers)
print("Y", Y.hex())
for i, s in enumerate(share_list):
    print("share", i, s.hex())

print("finish", round(time() - start, 3), "Sec")

all_parties = pair_list.copy()
shuffle(all_parties)
parties_index = list()
for _ in range(m):
    parties_index.append(all_parties.pop())
del all_parties
parties_index = [x.my_index for x in parties_index]
parties_index.sort()
print("3..", round(time() - start, 3), "Sec")
print("parties_index", parties_index)

eph_list = list()
for _ in range(m):
    k = PyThresholdKey.generate(t, m, parties_index)
    eph_list.append(k)

print("4..", round(time() - start, 3), "Sec")

eph_vss_points = list()
eph_scalars = list()
for e in eph_list:
    vss, sec = e.get_variable_secret_sharing()
    eph_vss_points.append(vss)
    eph_scalars.append(sec)

print("5..", round(time() - start, 3), "Sec")

eph_signers = [x.keypair.get_public_key() for x in eph_list]

eph_share_list = list()
for e in eph_list:
    eph_share_list.append(e.keygen_t_n_parties(eph_signers, eph_vss_points, eph_scalars))

print("6..", round(time() - start, 3), "Sec")

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

print("7..", round(time() - start, 3), "Sec")

sigma = summarize_local_signature(t, n, m, e, gamma_list, parties_index, vss_points, eph_vss_points)
print("finish", round(time() - start, 3), "Sec")
print("sigma", sigma.hex())

print("8..", round(time() - start, 3), "Sec")

sign_start = time()
r = verify_threshold_sign(sigma, Y, V, msg)
print("verify?", r, round((time()-sign_start)*1000), "mSec")
print("finish", round(time() - start, 3), "Sec")
