use crate::protocols::aggsig::{verify, verify_partial, EphemeralKey, KeyAgg, KeyPair};
use crate::python::utils::{bytes2point,bigint2bytes};
use crate::python::pykeypair::PyKeyPair;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::{PyBytes,PyBool,PyList,PyTuple,PyType,PyAny};


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
    fn new(obj: &PyRawObject) {
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::new_random();
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        let (commitment, blind_factor) = HashCommitment::create_commitment(
            &public.bytes_compressed_to_big_int());
        let keypair = PyKeyPair {secret, public};
        obj.init(PyEphemeralKey {keypair, commitment, blind_factor});
    }

    #[classmethod]
    fn from_keypair(cls: &PyType, keypair: &PyKeyPair) -> PyResult<PyEphemeralKey> {
        let (commitment, blind_factor) = HashCommitment::create_commitment(
            &keypair.public.bytes_compressed_to_big_int());
        let keypair = keypair.clone();
        Ok(PyEphemeralKey {keypair, commitment, blind_factor})
    }

    fn get_single_sign(&self, _py: Python, message: &PyBytes) -> Py<PyTuple> {
        let message = message.as_bytes();
        let base_point: GE = ECPoint::generator();
        let hash_private_key_message =
            HSha256::create_hash(&[&self.keypair.secret.to_big_int(), &BigInt::from(message)]);
        let ephemeral_private_key: FE = ECScalar::from(&hash_private_key_message);
        let ephemeral_public_key = base_point.scalar_mul(&ephemeral_private_key.get_element());
        let (commitment, blind_factor) =
            HashCommitment::create_commitment(&ephemeral_public_key.bytes_compressed_to_big_int());
        // compute c = H0(Rtag || apk || message)
        let c = EphemeralKey::hash_0(
            &ephemeral_public_key,
            &self.keypair.public,
            message,
            false,
        );
        // sign
        let c_fe: FE = ECScalar::from(&c);
        let a_fe: FE = ECScalar::from(&BigInt::from(1));
        let s_fe = ephemeral_private_key.clone() + (c_fe * self.keypair.secret.clone() * a_fe);
        let s_tag = s_fe.to_big_int();
        // signature s:
        let (R, s) = EphemeralKey::add_signature_parts(
            s_tag,
            &BigInt::from(0),
            &ephemeral_public_key,
        );
        PyTuple::new(_py, &[
            PyBytes::new(_py, &bigint2bytes(&R).unwrap()),
            PyBytes::new(_py, &bigint2bytes(&s).unwrap()),
        ])
    }

    fn check_commitments(&self) -> bool {
        EphemeralKey::test_com(
            &self.keypair.public, &self.blind_factor, &self.commitment)
    }
}

#[pyclass]
pub struct PyAggregate {
    #[pyo3(get)]
    pub keypair: PyKeyPair,
    #[pyo3(get)]
    pub eph: PyEphemeralKey,
    pub agg: KeyAgg,
    pub r_tag: GE,
    #[pyo3(get)]
    pub is_musig: bool,
}

#[pymethods]
impl PyAggregate {
    #[classmethod]
    fn generate(cls: &PyType, signers: &PyList, ephemeral: &PyList, keypair: &PyKeyPair, eph: &PyEphemeralKey)
        -> PyResult<PyAggregate> {
        // check signature number
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
        let mut pks = vec![];
        let mut party_index: Option<usize> = None;
        for (index, key) in signers.into_iter().enumerate() {
            let key: &PyBytes = key.try_into()?;
            let public = match bytes2point(key.as_bytes()) {
                Ok(public) => public,
                Err(_) => return Err(ValueError::py_err("invalid public key, 33 or 65 bytes length?"))
            };
            pks.push(public);
            if public == keypair.public {
                party_index = Some(index)
            }
        };
        let party_index = party_index.ok_or(
            ValueError::py_err("not found your public key in signers"))?;
        let agg = KeyAgg::key_aggregation_n(&pks, party_index);
        // compute R' = R1+R2:
        let mut points = vec![];
        for eph in ephemeral.into_iter() {
            let eph: &PyBytes = eph.try_into()?;
            match bytes2point(eph.as_bytes()) {
                Ok(eph) => points.push(eph),
                Err(_) => return Err(ValueError::py_err("invalid ephemeral key, 33 or 65 bytes length?"))
            };
        };
        let mut r_hat = points.remove(0);
        for p in points {
            r_hat = p + r_hat;
        };
        Ok(PyAggregate {keypair, eph, agg, r_tag: r_hat, is_musig})
    }

    fn get_partial_sign(&self, _py: Python, message: &PyBytes) -> Py<PyBytes> {
        // compute c = H0(Rtag || apk || message)
        let message = message.as_bytes();
        let c = EphemeralKey::hash_0(&self.r_tag, &self.agg.apk, message, self.is_musig);
        // compute partial signature s_i
        let c_fe: FE = ECScalar::from(&c);
        let a_fe: FE = ECScalar::from(&self.agg.hash);
        let s_i = self.eph.keypair.secret.clone() + (c_fe * self.keypair.secret.clone() * a_fe);
        // encode to bytes
        let s_i = bigint2bytes(&s_i.to_big_int()).unwrap();
        PyBytes::new(_py, &s_i)
    }

    fn R(&self, _py: Python) -> Py<PyBytes> {
        let int = self.r_tag.x_coor().unwrap();
        let bytes = bigint2bytes(&int).unwrap();
        PyBytes::new(_py, &bytes)
    }

    fn apk(&self, _py: Python) -> Py<PyBytes> {
        let mut bytes = self.agg.apk.get_element().serialize();
        if self.is_musig {
            bytes[0] += 3; // 0x02 0x03 0x04 => 0x05 0x06 0x07
        }
        PyBytes::new(_py, &bytes)
    }

    fn add_signature_parts(&self, _py: Python,  s1: &PyBytes, s2: &PyBytes) -> Py<PyBytes> {
        let s1 = BigInt::from(s1.as_bytes());
        let s2 = BigInt::from(s2.as_bytes());
        let s1_fe: FE = ECScalar::from(&s1);
        let s2_fe: FE = ECScalar::from(&s2);
        let s1_plus_s2 = s1_fe.add(&s2_fe.get_element());
        let s = bigint2bytes(&s1_plus_s2.to_big_int()).unwrap();
        PyBytes::new(_py, &s)
    }
}