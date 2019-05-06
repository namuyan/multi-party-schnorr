use crate::protocols::aggsig::{EphemeralKey, KeyAgg};
use crate::python::pyo3utils::{bytes2point, bigint2bytes};
use crate::python::pykeypair::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::{PyBytes,PyList,PyType};


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
        let keypair = generate_keypair();
        let (commitment, blind_factor) = HashCommitment::create_commitment(
            &keypair.public.bytes_compressed_to_big_int());
        obj.init(PyEphemeralKey {keypair, commitment, blind_factor});
    }

    #[classmethod]
    fn from_keypair(_cls: &PyType, keypair: &PyKeyPair) -> PyResult<PyEphemeralKey> {
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
    fn generate(_cls: &PyType, signers: &PyList, ephemeral: &PyList, keypair: &PyKeyPair, eph: &PyEphemeralKey)
        -> PyResult<PyAggregate> {
        // check signature number
        let signers: Vec<Vec<u8>> = signers.extract()?;
        let ephemeral: Vec<Vec<u8>> = ephemeral.extract()?;
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
            let public = bytes2point(key.as_slice())?;
            pks.push(public);
            if public == keypair.public {
                party_index = Some(index)
            }
        };
        let party_index = party_index.ok_or(
            ValueError::py_err("not found your public key in signers"))?;
        let agg = KeyAgg::key_aggregation_n(&pks, party_index);
        // compute R' = R1+R2:
        let mut points = Vec::with_capacity(ephemeral.len());
        for eph in ephemeral.into_iter() {
            let eph = bytes2point(eph.as_slice())?;
            points.push(eph);
        };
        // sum of ephemeral points
        let r_hat = {
            let mut iter = points.into_iter();
            let head = iter.next().unwrap();
            iter.fold(head, |a, b| a + b)
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
