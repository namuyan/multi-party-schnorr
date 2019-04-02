use crate::python::pykeypair::*;
use crate::python::utils::*;
use crate::python::pyagg::{PyAggregate,PyEphemeralKey};
use crate::protocols::aggsig::verify;
use curv::BigInt;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::{PyBytes,PyBool};
use pyo3::exceptions::ValueError;


#[pyfunction]
fn verify_aggregate_sign(_py: Python, sig: &PyBytes, R: &PyBytes, apk: &PyBytes, message: &PyBytes, is_musig: Option<bool>)
    -> PyResult<PyObject> {
    let sig = BigInt::from(sig.as_bytes());
    let R = BigInt::from(R.as_bytes());
    let mut is_musig = match is_musig {
        Some(is_musig) => is_musig,
        None => match decode_public_bytes(apk.as_bytes()) {
            Ok((is_musig, prefix)) => is_musig,
            Err(_) => return Err(ValueError::py_err("cannot find prefix and is_musig"))
        }
    };
    let apk = match bytes2point(apk.as_bytes()) {
        Ok(apk) => apk,
        Err(_) => return Err(ValueError::py_err("invalid apk"))
    };
    let message = message.as_bytes();
    let is_verify = verify(&sig, &R, &apk, message, is_musig).is_ok();
    Ok(PyObject::from(PyBool::new(_py, is_verify)))
}

#[pymodule]
pub fn multi_party_schnorr(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyEphemeralKey>()?;
    m.add_class::<PyAggregate>()?;
    m.add_wrapped(wrap_pyfunction!(verify_aggregate_sign))?;
    Ok(())
}
