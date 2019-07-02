use crate::pykeypair::*;
use crate::pyo3utils::*;
use crate::pyagg::{PyAggregate,PyEphemeralKey,verify_aggregate_signature};
use crate::pythreshold::*;
use crate::verifyutils::verify_auto_signature;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::{PyBytes, PyList, PyTuple};
use pyo3::exceptions::ValueError;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;


/// verify_aggregate_sign(sig: bytes, R: bytes, apk: bytes, message: bytes, is_musig=None) -> bool
/// --
///
/// verify aggregate signature (1of 1 and n of n)
/// signature: [sig 32bytes]-[R 32bytes]
/// publicKey: [apk 33bytes]
#[pyfunction]
fn verify_aggregate_sign(_py: Python, sig: &PyBytes, R: &PyBytes, apk: &PyBytes, message: &PyBytes, is_musig: Option<bool>)
    -> PyResult<PyObject> {
    let sig = BigInt::from(sig.as_bytes());
    let R = BigInt::from(R.as_bytes());
    let is_musig = match is_musig {
        Some(is_musig) => is_musig,
        None => match decode_public_bytes(apk.as_bytes()) {
            Ok((key_type, _)) => match key_type {
                PyKeyType::SingleSig => false,
                PyKeyType::AggregateSig => true,
                _ => return Err(ValueError::py_err("not found pubkey prefix"))
            },
            Err(_) => return Err(ValueError::py_err("cannot find prefix and is_musig"))
        }
    };
    let apk = bytes2point(apk.as_bytes())?;
    let message = message.as_bytes();
    let is_verify = verify_aggregate_signature(&sig, &R, &apk, message, is_musig).is_ok();
    Ok(is_verify.to_object(_py))
}

/// verify_auto(s: bytes, r: bytes, apk: bytes, message: bytes) -> bool
/// --
///
/// verify signature with detection of type (1 of 1, n of n and n of m)
#[pyfunction]
fn verify_auto(_py: Python, s: &PyBytes, r: &PyBytes, apk: &PyBytes, message: &PyBytes)
    -> PyResult<PyObject> {
    let s = s.as_bytes();
    let r = r.as_bytes();
    let apk = apk.as_bytes();
    let message = message.as_bytes();
    let is_verify = _py.allow_threads(move || {
        verify_auto_signature(s, r, apk, message)
    }).map_err(|err| ValueError::py_err(err))?;
    Ok(is_verify.to_object(_py))
}

/// verify_auto_multi(tasks: list, n_workers: int, f_raise: bool) -> List[bool]
/// --
///
/// verify many signature with detection on multi-core(1 of 1, n of n and n of m)
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
    let exception = _py.allow_threads(move || {
        let mut response = Vec::with_capacity(n_jobs);
        for result in rx.iter().take(n_jobs) {
            let is_verify = match result {
                Ok(is_verify) => is_verify,
                Err(err) => {
                    if f_raise {
                        return Err(err)
                    }
                    false
                }
            };
            response.push(is_verify);
        };
        Ok(response)
    });
    match exception {
        Ok(response) => Ok(response.to_object(_py)),
        Err(err) => Err(ValueError::py_err(err))
    }
}

/// summarize_public_points(signers: list) -> bytes
/// --
///
/// return sum of public points with prefix +6
/// used for threshold-signature
#[pyfunction]
fn summarize_public_points(_py: Python, signers: &PyList) -> PyResult<PyObject> {
    let signers = pylist2points(&signers)?;
    let sum = sum_public_points(&signers)?;
    let mut sum = sum.get_element().serialize_compressed();
    sum[0] += 6;  // 0x02 0x03 0x04 => 0x08 0x09 0x0a
    Ok(PyBytes::new(_py, &sum).to_object(_py))
}

/// get_local_signature(share: bytes, eph_share: bytes, Y: bytes, V: bytes, message: bytes) -> (bytes, bytes)
/// --
///
/// return e and gamma
/// used for threshold-signature
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

/// summarize_local_signature(t: int, n: int, m: int, e: int, gammas: list, parties_index: list, vss_points: list, eph_vss_points: list) -> bytes
/// --
///
/// return sigma
/// used for threshold-signature
#[pyfunction]
fn summarize_local_signature(
    _py: Python, t: usize, n: usize, m: usize, e: &PyBytes, gammas: &PyList,
    parties_index: &PyList, vss_points: &PyList, eph_vss_points: &PyList)
    -> PyResult<PyObject> {
    let e: FE = ECScalar::from(&BigInt::from(e.as_bytes()));
    let gammas: Vec<FE> = pylist2bigint(gammas)?.iter()
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

/// verify_threshold_sign(sigma: bytes, Y: bytes, V: bytes, message: bytes) -> bool
/// --
///
/// verify threshold signature
/// signature: [sigma 32bytes]-[V 33bytes]
/// publicLey: [Y 33bytes]
#[pyfunction]
fn verify_threshold_sign(sigma: &PyBytes, Y: &PyBytes, V: &PyBytes, message: &PyBytes)
    -> PyResult<bool> {
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
