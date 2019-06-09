use crate::python::pyo3utils::{bytes2point, bigint2bytes};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType, PyTuple};
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use protocols::aggsig::EphemeralKey;

#[pyclass]
#[derive(Clone)]
pub struct PyKeyPair {
    pub secret: FE,
    pub public: GE,
}

#[pymethods]
impl PyKeyPair {
    #[new]
    fn new(obj: &PyRawObject) {
        obj.init(generate_keypair());
    }

    #[classmethod]
    fn from_secret_key(_cls: &PyType, secret: &PyBytes) -> PyResult<PyKeyPair> {
        let secret = secret.as_bytes();
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::from(&BigInt::from(secret));
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        Ok(PyKeyPair {secret, public})
    }

    fn get_secret_key(&self, _py: Python) -> PyObject {
        let secret = self.secret.to_big_int();
        let bytes = bigint2bytes(&secret).unwrap();
        PyBytes::new(_py, &bytes).to_object(_py)
    }

    fn get_public_key(&self, _py: Python) -> PyObject {
        let public = self.public.get_element().serialize();
        PyBytes::new(_py, &public).to_object(_py)
    }

    fn get_single_sign(&self, _py: Python, message: &PyBytes) -> PyObject {
        let message = message.as_bytes();
        let base_point: GE = ECPoint::generator();
        let hash_private_key_message =
            HSha256::create_hash(&[&self.secret.to_big_int(), &BigInt::from(message)]);
        let ephemeral_private_key: FE = ECScalar::from(&hash_private_key_message);
        let ephemeral_public_key = base_point.scalar_mul(&ephemeral_private_key.get_element());
        //let (commitment, blind_factor) =
        //    HashCommitment::create_commitment(&ephemeral_public_key.bytes_compressed_to_big_int());
        // compute c = H0(Rtag || apk || message)
        let c = EphemeralKey::hash_0(
            &ephemeral_public_key,
            &self.public,
            message,
            false,
        );
        // sign
        let c_fe: FE = ECScalar::from(&c);
        let a_fe: FE = ECScalar::from(&BigInt::from(1));
        let s_fe = ephemeral_private_key.clone() + (c_fe * self.secret.clone() * a_fe);
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
        ]).to_object(_py)
    }

    /// do not forget to pass through a hash function
    fn get_shared_point(&self, _py: Python, public: &PyBytes) -> PyResult<PyObject> {
        let public: GE = bytes2point(public.as_bytes())?;
        let point: GE = public.scalar_mul(&self.secret.get_element());
        let point = point.get_element().serialize();
        Ok(PyObject::from(PyBytes::new(_py, &point)))
    }
}

pub fn generate_keypair() -> PyKeyPair {
    let ec_point: GE = ECPoint::generator();
    let secret: FE = ECScalar::new_random();
    let public: GE = ec_point.scalar_mul(&secret.get_element());
    PyKeyPair {secret, public}
}
