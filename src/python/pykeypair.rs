use crate::protocols::aggsig::{verify, verify_partial, EphemeralKey, KeyAgg, KeyPair};
use crate::python::bin2pub::public_from_bytes;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use curv::arithmetic::traits::Converter;
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::{PyBytes,PyBool,PyList,PyTuple,PyType,PyAny};

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
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::new_random();
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        obj.init(PyKeyPair {secret, public});
    }

    #[classmethod]
    fn from_secret_key(cls: &PyType, secret: &PyBytes) -> PyResult<PyKeyPair> {
        let secret = secret.as_bytes();
        let ec_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::from(&BigInt::from(secret));
        let public: GE = ec_point.scalar_mul(&secret.get_element());
        Ok(PyKeyPair {secret, public})
    }

    fn get_secret_key(&self, _py: Python) -> Py<PyBytes> {
        let secret = self.secret.to_big_int();
        let secret = BigInt::to_vec(&secret);
        PyBytes::new(_py, secret.as_slice())
    }

    fn get_public_key(&self, _py: Python) -> Py<PyBytes> {
        let public = self.public.get_element().serialize();
        // let public = self.public.get_element().serialize_uncompressed();
        PyBytes::new(_py, &public)
    }
    /// do not forget to pass through a hash function
    fn get_shared_point(&self, _py: Python, public: &PyBytes) -> PyResult<PyObject> {
        let public: GE = match public_from_bytes(public.as_bytes()){
            Ok(public) => public,
            Err(_) => return Err(ValueError::py_err("invalid public key, 33 or 65 bytes length?"))
        };
        let point: GE = public.scalar_mul(&self.secret.get_element());
        let point = point.get_element().serialize();
        Ok(PyObject::from(PyBytes::new(_py, &point)))
    }
}

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
            let public = match public_from_bytes(key.as_bytes()) {
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
        let mut r_hat = GE::generator();
        for eph in ephemeral.into_iter() {
            let eph: &PyBytes = eph.try_into()?;
            let eph = match public_from_bytes(eph.as_bytes()) {
                Ok(eph) => eph,
                Err(_) => return Err(ValueError::py_err("invalid ephemeral key, 33 or 65 bytes length?"))
            };
            r_hat = r_hat.add_point(&eph.get_element());
        }
        r_hat = r_hat.sub_point(&GE::generator().get_element());
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
        let s_i = BigInt::to_vec(&s_i.to_big_int());
        PyBytes::new(_py, s_i.as_slice())
    }

    fn R(&self, _py: Python) -> Py<PyBytes> {
        let bytes = self.r_tag.x_coor().unwrap();
        let bytes = BigInt::to_vec(&bytes);
        PyBytes::new(_py, bytes.as_slice())
    }

    fn apk(&self, _py: Python) -> Py<PyBytes> {
        let bytes = self.agg.apk.get_element().serialize();
        PyBytes::new(_py, &bytes)
    }

    fn add_signature_parts(&self, _py: Python,  s1: &PyBytes, s2: &PyBytes) -> Py<PyTuple> {
        let s1 = BigInt::from(s1.as_bytes());
        let s2 = BigInt::from(s2.as_bytes());
        let (R, s) = EphemeralKey::add_signature_parts(s1, &s2, &self.r_tag);
        let R = BigInt::to_vec(&R);
        let s = BigInt::to_vec(&s);
        PyTuple::new(_py, &[
            PyBytes::new(_py, R.as_slice()),
            PyBytes::new(_py, s.as_slice()),
        ])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ecdhe() {
        let ec_point0: GE = ECPoint::generator();
        let secret0: FE = ECScalar::new_random();
        let public0: GE = ec_point0.scalar_mul(&secret0.get_element());
        let ec_point1: GE = ECPoint::generator();
        let secret1: FE = ECScalar::new_random();
        let public1: GE = ec_point1.scalar_mul(&secret1.get_element());
        assert_ne!(secret0, secret1);
        assert_ne!(public0, public1);
        let mux01 = public0.scalar_mul(&secret1.get_element());
        let mux10 = public1.scalar_mul(&secret0.get_element());
        assert_eq!(mux01.pk_to_key_slice(), mux10.pk_to_key_slice());
        let byte = public0.get_element().serialize();
        println!("{:?}", byte[0]);
        println!("x0:{:?}", public0.x_coor().unwrap());
        println!("y0:{:?}", public0.y_coor().unwrap());
        let public2: GE = public_from_bytes(&byte).expect("Why?");
        println!("x2:{:?}", public2.x_coor().unwrap());
        println!("y2:{:?}", public2.y_coor().unwrap());
        assert_eq!(public0, public2);
    }

    #[test]
    fn add_point() {
        let a0 = GE::random_point();
        let a1 = GE::random_point();
        let r_direct = a0.add_point(&a1.get_element());
        let mut g = GE::generator();
        g = a0 + g;
        g = a1 + g;
        g = g.sub_point(&GE::generator().get_element());
        assert_eq!(r_direct, g);
    }
}

