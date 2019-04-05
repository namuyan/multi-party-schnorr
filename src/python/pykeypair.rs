use crate::python::utils::{bytes2point,bigint2bytes};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::types::{PyBytes,PyTuple,PyType};

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

    fn get_secret_key(&self, _py: Python) -> Py<PyBytes> {
        let secret = self.secret.to_big_int();
        let bytes = bigint2bytes(&secret).unwrap();
        PyBytes::new(_py, &bytes)
    }

    fn get_public_key(&self, _py: Python) -> Py<PyBytes> {
        let public = self.public.get_element().serialize();
        PyBytes::new(_py, &public)
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
