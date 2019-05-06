use crate::python::pykeypair::*;
use crate::python::pyo3utils::*;
use crate::python::pyagg::{PyAggregate,PyEphemeralKey};
use crate::python::pythreshold::*;
use crate::python::verifyutils::verify_auto_signature;
use crate::protocols::aggsig::verify;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::{PyBytes, PyList, PyTuple, PyBool};
use pyo3::exceptions::ValueError;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;


#[pyfunction]
fn verify_aggregate_sign(_py: Python, sig: &PyBytes, R: &PyBytes, apk: &PyBytes, message: &PyBytes, is_musig: Option<bool>)
    -> PyResult<PyObject> {
    // signature -> [sig 32bytes]-[R 33bytes]
    // public    -> [apk 33bytes]
    let sig = BigInt::from(sig.as_bytes());
    let R = BigInt::from(R.as_bytes());
    let is_musig = match is_musig {
        Some(is_musig) => is_musig,
        None => match decode_public_bytes(apk.as_bytes()) {
            Ok((key_type, _)) => match key_type {
                KeyType::SingleSig => false,
                KeyType::AggregateSig => true,
                _ => return Err(ValueError::py_err("not found pubkey prefix"))
            },
            Err(_) => return Err(ValueError::py_err("cannot find prefix and is_musig"))
        }
    };
    let apk = bytes2point(apk.as_bytes())?;
    let message = message.as_bytes();
    let is_verify = verify(&sig, &R, &apk, message, is_musig).is_ok();
    Ok(PyObject::from(PyBool::new(_py, is_verify)))
}

#[pyfunction]
fn verify_auto(_py: Python, s: &PyBytes, r: &PyBytes, apk: &PyBytes, message: &PyBytes)
    -> PyResult<PyObject> {
    let s = s.as_bytes();
    let r = r.as_bytes();
    let apk = apk.as_bytes();
    let message = message.as_bytes();
    let is_verify = verify_auto_signature(s, r, apk, message).map_err(
        |err| ValueError::py_err(err))?;
    Ok(is_verify.to_object(_py))
}

#[pyfunction]
fn verify_auto_multi(_py: Python, tasks: &PyList, n_workers: usize, f_raise: bool)
    -> PyResult<PyObject> {
    // verify by multi-threading
    let tasks: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = tasks.extract()?;
    let pool = ThreadPool::new(n_workers);
    let (tx, rx) = channel();
    let n_jobs = tasks.len();
    for (s, r, apk, message) in tasks {
        let tx = tx.clone();
        pool.execute(move || {
            tx.send(verify_auto_signature(&s, &r, &apk, &message)).unwrap()
        });
    };
    let mut response = Vec::with_capacity(n_jobs);
    for result in rx.iter().take(n_jobs) {
        let is_verify = match result {
            Ok(is_verify) => is_verify,
            Err(err) => {
                if f_raise {
                    return Err(ValueError::py_err(err))
                }
                false
            }
        };
        response.push(is_verify);
    };
    Ok(response.to_object(_py))
}

#[pyfunction]
fn summarize_public_points(_py: Python, signers: &PyList) -> PyResult<PyObject> {
    let signers = pylist2points(&signers)?;
    let sum = sum_public_points(&signers)?;
    let mut sum = sum.get_element().serialize();
    sum[0] += 6;  // 0x02 0x03 0x04 => 0x08 0x09 0x0a
    Ok(PyObject::from(PyBytes::new(_py, &sum)))
}

#[pyfunction]
fn get_local_signature(_py: Python, share: &PyBytes, eph_share: &PyBytes, Y: &PyBytes, V: &PyBytes, message: &PyBytes)
    -> PyResult<PyObject> {
    let share: FE = ECScalar::from(&BigInt::from(share.as_bytes()));
    let eph_share: FE = ECScalar::from(&BigInt::from(eph_share.as_bytes()));
    let Y: GE = bytes2point(Y.as_bytes())?;  // sharedKey
    let V: GE = bytes2point(V.as_bytes())?;  // eph sharedKey
    let message = message.as_bytes();
    let (e, gamma_i) = compute_local_signature(&share, &eph_share, &Y, &V, message);
    let e = bigint2bytes(&e.to_big_int()).unwrap();
    let gamma_i = bigint2bytes(&gamma_i.to_big_int()).unwrap();
    Ok(PyTuple::new(_py, &[
        PyBytes::new(_py, &e),
        PyBytes::new(_py, &gamma_i),
    ]).to_object(_py))
}

#[pyfunction]
fn summarize_local_signature(
    _py: Python, t: usize, n: usize, m: usize, e: &PyBytes, gammas: &PyList, parties_index: &PyList,
    vss_points: &PyList, eph_vss_points: &PyList) -> PyResult<PyObject> {
    let e: FE = ECScalar::from(&BigInt::from(e.as_bytes()));
    let gammas: Vec<FE> = pylist2bigints(gammas)?.iter()
        .map(|int| ECScalar::from(int)).collect();
    let mut tmp = Vec::with_capacity(parties_index.len());
    for int in parties_index.iter() {
        let int: usize = int.extract()?;
        tmp.push(int);
    }
    let parties_index = tmp;
    let vss_points = pylist2vss(t, n, vss_points)?;
    let eph_vss_points = pylist2vss(t, m, eph_vss_points)?;
    match sum_local_signature(t, &e, &gammas, &parties_index, &vss_points, &eph_vss_points){
        Ok(sigma) => {
            let sigma = bigint2bytes(&sigma.to_big_int()).unwrap();
            Ok(PyBytes::new(_py, &sigma).to_object(_py))
        },
        Err(err) => Err(ValueError::py_err(err))
    }
}

#[pyfunction]
fn verify_threshold_sign(sigma: &PyBytes, Y: &PyBytes, V: &PyBytes, message: &PyBytes) -> PyResult<bool> {
    // signature -> [sigma 32bytes]-[V 33bytes]
    // public    -> [Y 33bytes]
    let sigma = ECScalar::from(&BigInt::from(sigma.as_bytes()));
    let Y = bytes2point(Y.as_bytes())?;
    let V = bytes2point(V.as_bytes())?;
    let verify = verify_threshold_signature(sigma, &Y, &V, message.as_bytes());
    Ok(verify)
}

#[pymodule]
pub fn multi_party_schnorr(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyEphemeralKey>()?;
    m.add_class::<PyAggregate>()?;
    m.add_wrapped(wrap_pyfunction!(verify_aggregate_sign))?;
    m.add_wrapped(wrap_pyfunction!(verify_auto))?;
    m.add_wrapped(wrap_pyfunction!(verify_auto_multi))?;
    m.add_class::<PyThresholdKey>()?;
    m.add_wrapped(wrap_pyfunction!(summarize_public_points))?;
    m.add_wrapped(wrap_pyfunction!(get_local_signature))?;
    m.add_wrapped(wrap_pyfunction!(summarize_local_signature))?;
    m.add_wrapped(wrap_pyfunction!(verify_threshold_sign))?;
    Ok(())
}
