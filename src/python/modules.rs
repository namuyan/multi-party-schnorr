use crate::python::pykeypair::*;
use crate::python::pyagg::{PyAggregate,PyEphemeralKey};
use crate::python::utils::bytes2point;
use crate::protocols::aggsig::verify;
use curv::BigInt;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::PyBytes;


#[pyfunction]
fn verify_aggregate_sign(sig: &PyBytes, R: &PyBytes, apk: &PyBytes, message: &PyBytes, is_musig: bool)
    -> bool {
    let sig = BigInt::from(sig.as_bytes());
    let R = BigInt::from(R.as_bytes());
    let apk = match bytes2point(apk.as_bytes()) {
        Ok(apk) => apk,
        Err(_) => return false
    };
    let message = message.as_bytes();
    verify(&sig, &R, &apk, message, is_musig).is_ok()
}

#[pymodule]
pub fn multi_party_schnorr(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyEphemeralKey>()?;
    m.add_class::<PyAggregate>()?;
    m.add_wrapped(wrap_pyfunction!(verify_aggregate_sign))?;
    Ok(())
}
