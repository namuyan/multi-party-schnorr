use crate::pyo3utils::{bytes2point, bigint2bytes};
use crate::pykeypair::*;
use crate::verifyutils::*;
use emerald_city::curv::cryptographic_primitives::commitments::{
    hash_commitment::HashCommitment,
    traits::Commitment,
};
use emerald_city::curv::cryptographic_primitives::hashing::{
    hash_sha256::HSha256,
    traits::Hash,
};
use emerald_city::curv::elliptic::curves::secp256_k1::{FE, GE};
use emerald_city::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use emerald_city::curv::arithmetic::num_bigint::BigInt;
use num_traits::{Zero, One};
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::{PyBytes, PyType};


#[pyclass]
#[derive(Clone)]
pub struct PyEphemeralKey {
    #[pyo3(get)]
    pub keypair: PyKeyPair,
    pub commitment: BigInt,
    pub blind_factor: BigInt,
}

#[pymethods]
impl PyEphemeralKey {
    #[new]
    fn new(py: Python) -> Self {
        let keypair = generate_keypair(py);
        let (commitment, blind_factor) = HashCommitment::create_commitment(
            &keypair.public.bytes_compressed_to_big_int());
        PyEphemeralKey {keypair, commitment, blind_factor}
    }

    /// from_keypair(keypair: PyKeyPair) -> PyEphemeralKey
    /// --
    ///
    /// get ephemeral key from keypair
    #[classmethod]
    fn from_keypair(_cls: &PyType, keypair: &PyKeyPair) -> PyResult<PyEphemeralKey> {
        let (commitment, blind_factor) = HashCommitment::create_commitment(
            &keypair.public.bytes_compressed_to_big_int());
        let keypair = keypair.clone();
        Ok(PyEphemeralKey {keypair, commitment, blind_factor})
    }

    /// check_commitments() -> bool
    /// --
    ///
    /// check ephemeral commitments
    fn check_commitments(&self) -> bool {
        ephemeral_test_com(&self.keypair.public, &self.blind_factor, &self.commitment)
    }
}

#[pyclass]
pub struct PyAggregate {
    #[pyo3(get)]
    pub keypair: PyKeyPair,
    #[pyo3(get)]
    pub eph: PyEphemeralKey,
    pub apk: GE,
    pub hash: BigInt,
    pub r_tag: GE,
    #[pyo3(get)]
    pub is_musig: bool,
}

#[pymethods]
impl PyAggregate {

    /// generate(signers: list, ephemeral: list, keypair: PyKeyPair, eph: PyEphemeralKey) -> PyAggregate
    /// --
    ///
    /// get aggregate key
    #[classmethod]
    fn generate(_cls: &PyType, signers: &PyAny, ephemeral: &PyAny, keypair: &PyKeyPair, eph: &PyEphemeralKey)
        -> PyResult<PyAggregate> {
        // check signature number
        let signers: Vec<&[u8]> = signers.extract()?;
        let ephemeral: Vec<&[u8]> = ephemeral.extract()?;
        let keypair = keypair.clone();
        let eph = eph.clone();
        if signers.len() != ephemeral.len() {
            return Err(ValueError::py_err(format!(
                "signers={} ephemeral={}, different?", signers.len(), ephemeral.len())))
        } else if signers.len() < 1 {
            return Err(ValueError::py_err("no signer found"))
        }
        // compute apk
        let is_musig = 1 < signers.len();
        let mut party_index: Option<usize> = None;
        let mut pks = Vec::with_capacity(signers.len());
        for (index, key) in signers.into_iter().enumerate() {
            let public = bytes2point(key)?;
            if public == keypair.public {
                party_index = Some(index)
            }
            pks.push(public);
        };
        let party_index = party_index.ok_or(
            ValueError::py_err("not found your public key in signers"))?;
        let (apk, hash) = key_aggregation_n(&pks, party_index);
        // compute R' = R1+R2:
        let mut points = Vec::with_capacity(ephemeral.len());
        for eph in ephemeral.into_iter() {
            let eph = bytes2point(eph)?;
            points.push(eph);
        };
        // sum of ephemeral points
        let r_hat = {
            let mut iter = points.into_iter();
            let head = iter.next().unwrap();
            iter.fold(head, |a, b| a + b)
        };
        Ok(PyAggregate {keypair, eph, apk, hash, r_tag: r_hat, is_musig})
    }

    /// get_partial_sign(message: bytes) -> bytes
    /// --
    ///
    /// get partial signature of whole's
    fn get_partial_sign(&self, _py: Python, message: &PyBytes) -> PyObject {
        // compute c = H0(Rtag || apk || message)
        let message = message.as_bytes();
        let c = ephemeral_hash_0(&self.r_tag, &self.apk, message, self.is_musig);
        // compute partial signature s_i
        let c_fe: FE = ECScalar::from(&c);
        let a_fe: FE = ECScalar::from(&self.hash);
        let s_i = self.eph.keypair.secret.clone() + (c_fe * self.keypair.secret.clone() * a_fe);
        // encode to bytes
        let s_i = bigint2bytes(&s_i.to_big_int()).unwrap();
        PyBytes::new(_py, &s_i).to_object(_py)
    }

    /// R() -> bytes
    /// --
    ///
    /// get R point
    fn R(&self, _py: Python) -> PyObject {
        let int = self.r_tag.x_coor().unwrap();
        let bytes = bigint2bytes(&int).unwrap();
        PyBytes::new(_py, &bytes).to_object(_py)
    }

    /// apk() -> bytes
    /// --
    ///
    /// get shared public key
    fn apk(&self, _py: Python) -> PyObject {
        let mut bytes = self.apk.get_element().serialize();
        if self.is_musig {
            bytes[0] += 3; // 0x02 0x03 0x04 => 0x05 0x06 0x07
        }
        PyBytes::new(_py, &bytes).to_object(_py)
    }

    /// add_signature_parts(s1: bytes, s2: bytes) -> bytes
    /// --
    ///
    /// return a signature + another signature
    fn add_signature_parts(&self, _py: Python,  s1: &PyBytes, s2: &PyBytes) -> PyObject {
        let s1 = BigInt::from_bytes_be(s1.as_bytes());
        let s2 = BigInt::from_bytes_be(s2.as_bytes());
        let s1_fe: FE = ECScalar::from(&s1);
        let s2_fe: FE = ECScalar::from(&s2);
        let s1_plus_s2 = s1_fe.add(&s2_fe.get_element());
        let s = bigint2bytes(&s1_plus_s2.to_big_int()).unwrap();
        PyBytes::new(_py, &s).to_object(_py)
    }
}


/// generate aggregate Key
fn key_aggregation_n(pks: &[GE], party_index: usize) -> (GE, BigInt) {
    let bn_1 = BigInt::one();
    let x_coor_vec: Vec<BigInt> = pks
        .iter()
        .map(|pk| pk.bytes_compressed_to_big_int())
        .collect();

    let hash_vec: Vec<BigInt> = x_coor_vec
        .iter()
        .map(|pk| {
            let mut vec = Vec::new();
            vec.push(&bn_1);
            vec.push(pk);
            for mpz in x_coor_vec.iter().take(pks.len()) {
                vec.push(mpz);
            }
            HSha256::create_hash(&vec)
        })
        .collect();

    let mut apk_vec: Vec<GE> = pks
        .iter()
        .zip(&hash_vec)
        .map(|(pk, hash)| {
            let hash_t: FE = ECScalar::from(&hash);
            let pki: GE = pk.clone();
            pki.scalar_mul(&hash_t.get_element())
        })
        .collect();

    let pk1 = apk_vec.remove(0);
    let sum = apk_vec
        .iter()
        .fold(pk1, |acc, pk| acc.add_point(&pk.get_element()));
    // apk, hash
    (sum, hash_vec[party_index].clone())
    }


// ephemeral commitments check
fn ephemeral_test_com(r_to_test: &GE, blind_factor: &BigInt, comm: &BigInt) -> bool {
    let computed_comm = &HashCommitment::create_commitment_with_user_defined_randomness(
        &r_to_test.bytes_compressed_to_big_int(),
        blind_factor,
    );
    computed_comm == comm
}


pub fn verify_aggregate_signature(signature: &BigInt, r_x: &BigInt, apk: &GE, message: &[u8], musig_bit: bool)
    -> Result<(), String> {
    let base_point: GE = ECPoint::generator();

    let c = if musig_bit {
        HSha256::create_hash(&[
            &BigInt::zero(),
            &r_x,
            &apk.bytes_compressed_to_big_int(),
            &BigInt::from_bytes_be(message),
        ])
    } else {
        HSha256::create_hash(&[
            r_x,
            &apk.bytes_compressed_to_big_int(),
            &BigInt::from_bytes_be(message),
        ])
    };

    let signature_fe: FE = ECScalar::from(signature);
    let sG = base_point.scalar_mul(&signature_fe.get_element());
    let c: FE = ECScalar::from(&c);
    let cY = apk.scalar_mul(&c.get_element());
    let sG = sG.sub_point(&cY.get_element());
    if sG.x_coor().unwrap() == *r_x {
        Ok(())
    } else {
        Err(String::from("sG_x do not match with r_x"))
    }
}


#[cfg(test)]
mod Test {
    use crate::pyo3utils::bytes2point_inner;
    use emerald_city::curv::arithmetic::num_bigint::BigInt;
    use pyagg::verify_aggregate_signature;

    #[test]
    fn test_normal_single_sig() {
        // let sk = b"\xb7\xe1Qb\x8a\xed*j\xbfqX\x80\x9c\xf4\xf3\xc7b\xe7\x16\x0f8\xb4\xdaV\xa7\x84\xd9\x04Q\x90\xcf\xef";
        let pk = b"\x02\xdf\xf1\xd7\x7f*g\x1c_6\x187&\xdb#A\xbeX\xfe\xae\x1d\xa2\xde\xce\xd8C$\x0f{P+\xa6Y";
        let msg = b"$?j\x88\x85\xa3\x08\xd3\x13\x19\x8a.\x03psD\xa4\t8\")\x9f1\xd0\x08.\xfa\x98\xecNl\x89";
        let sig_a = b"*)\x8d\xac\xaeW9Z\x15\xd0y]\xdb\xfd\x1d\xcbVM\xa8+\x0f&\x9b\xc7\nt\xf8\"\x04)\xba\x1d";
        let sig_b = b"\x1eQ\xa2,\xce\xc3U\x99\xb8\xf2f\x91\"\x81\xf86_\xfc-\x03Z#\x044\xa1\xa6M\xc5\x9fp\x13\xfd";

        let pk = bytes2point_inner(pk).unwrap();
        let sig_a = BigInt::from_bytes_be(sig_a);
        let sig_b = BigInt::from_bytes_be(sig_b);
        assert!(verify_aggregate_signature(&sig_b, &sig_a, &pk, msg, false).is_ok());
    }


    #[test]
    fn test_zerofill_single_sig() {
        // let sk = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let pk = b"\x02y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98";
        let msg = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let sig_a = b"xz\x84\x8eq\x04=(\x0cPG\x0e\x8e\x152\xb2\xdd] \xee\x91*E\xdb\xdd+\xd1\xdf\xbf\x18~\xf6";  // r
        let sig_b = b"p1\xa9\x881\x85\x9d\xc3M\xff\xee\xdd\xa8h1\x84,\xcd\x00y\xe1\xf9*\xf1w\xf7\xf2,\xc1\xdc\xed\x05";  // s

        let pk = bytes2point_inner(pk).unwrap();
        let sig_a = BigInt::from_bytes_be(sig_a);
        let sig_b = BigInt::from_bytes_be(sig_b);
        assert!(verify_aggregate_signature(&sig_b, &sig_a, &pk, msg, false).is_ok());
    }
}
