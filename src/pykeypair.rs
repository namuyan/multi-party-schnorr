use crate::pyo3utils::{bytes2point, bigint2bytes};
use crate::verifyutils::*;
use emerald_city::curv::cryptographic_primitives::hashing::{
    hash_sha256::HSha256,
    traits::Hash,
};
use emerald_city::curv::elliptic::curves::secp256_k1::{FE, GE};
use emerald_city::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use emerald_city::curv::arithmetic::num_bigint::BigInt;
use num_traits::{Zero, One};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType, PyTuple};


#[pyclass]
#[derive(Clone)]
pub struct PyKeyPair {
    pub secret: FE,
    pub public: GE,
}

#[pymethods]
impl PyKeyPair {
    #[new]
    fn new(py: Python) -> Self {
        generate_keypair(py)
    }

    /// from_secret_key(secret: bytes) -> PyKeyPair
    /// --
    ///
    /// generate keypair from secret key
    #[classmethod]
    fn from_secret_key(_cls: &PyType, secret: &PyBytes) -> PyResult<PyKeyPair> {
        let secret = secret.as_bytes();
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::from(&BigInt::from_bytes_be(secret));
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        Ok(PyKeyPair {secret, public})
    }

    /// get_secret_key() -> bytes
    /// --
    ///
    /// get secret key
    fn get_secret_key(&self, _py: Python) -> PyObject {
        let secret = self.secret.to_big_int();
        let bytes = bigint2bytes(&secret).unwrap();
        PyBytes::new(_py, &bytes).to_object(_py)
    }

    /// get_public_key() -> bytes
    /// --
    ///
    /// get public key
    fn get_public_key(&self, _py: Python) -> PyObject {
        let public = self.public.get_element().serialize();
        PyBytes::new(_py, &public).to_object(_py)
    }

    /// get_single_sign(message: bytes) -> tuple
    /// --
    ///
    /// get signature from single signer
    /// return R(32b) and s(32b)
    fn get_single_sign(&self, _py: Python, message: &PyBytes) -> PyObject {
        let message = message.as_bytes();
        let base_point: GE = ECPoint::generator();
        let hash_private_key_message =
            HSha256::create_hash(&[&self.secret.to_big_int(), &BigInt::from_bytes_be(message)]);
        let ephemeral_private_key: FE = ECScalar::from(&hash_private_key_message);
        let ephemeral_public_key = base_point.scalar_mul(&ephemeral_private_key.get_element());
        //let (commitment, blind_factor) =
        //    HashCommitment::create_commitment(&ephemeral_public_key.bytes_compressed_to_big_int());
        // compute c = H0(Rtag || apk || message)
        let c = ephemeral_hash_0(
            &ephemeral_public_key,
            &self.public,
            message,
            false,
        );
        // sign
        let c_fe: FE = ECScalar::from(&c);
        let a_fe: FE = ECScalar::from(&BigInt::one());
        let s_fe = ephemeral_private_key.clone() + (c_fe * self.secret.clone() * a_fe);
        let s_tag = s_fe.to_big_int();
        // signature s:
        let R = ephemeral_public_key.x_coor().unwrap();
        let s = add_scalar_parts(s_tag, &BigInt::zero());
        PyTuple::new(_py, &[
            PyBytes::new(_py, &bigint2bytes(&R).unwrap()),
            PyBytes::new(_py, &bigint2bytes(&s).unwrap()),
        ]).to_object(_py)
    }

    /// get_shared_point(public: bytes) -> bytes
    /// --
    ///
    /// get shared point by multiple with public key
    fn get_shared_point(&self, _py: Python, public: &PyBytes) -> PyResult<PyObject> {
        // note: do not forget to pass through a hash function
        let public: GE = bytes2point(public.as_bytes())?;
        let point: GE = public.scalar_mul(&self.secret.get_element());
        let point = point.get_element().serialize();
        Ok(PyBytes::new(_py, &point).to_object(_py))
    }
}

pub fn generate_keypair(_py: Python) -> PyKeyPair {
    // release GIL
    _py.allow_threads(move || {
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::new_random();
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        PyKeyPair {secret, public}
    })
}
