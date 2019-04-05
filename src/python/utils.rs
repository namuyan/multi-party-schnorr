use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing};
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt,GE,PK};
use curv::arithmetic::traits::Converter;
use curv::ErrorKey;
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::{PyList, PyBytes, PyTuple};


/// Bitcoin public key format converter
/// compressed key   : 2 or 3 prefix + X
/// uncompressed key : 4 prefix      + X + Y
pub fn bytes2point(bytes: &[u8]) -> PyResult<GE> {
    let len = bytes.len();
    let result = match decode_public_bytes(bytes) {
        Ok((is_musig, prefix)) => {
            if len == 33 && (prefix == 2 || prefix == 3) {
                let mut bytes = bytes.to_vec();
                if is_musig {
                    bytes[0] -= 3;
                }
                let public = PK::from_slice(&bytes)
                    .map_err(|_| ValueError::py_err("decode failed key"))?;
                GE::from_bytes(&public.serialize_uncompressed()[1..])
            }else if len == 65 && prefix == 4 {
                GE::from_bytes(&bytes[1..])
            } else {
                Err(ErrorKey::InvalidPublicKey)
            }
        },
        Err(err) => Err(err)
    };
    result.map_err(|_| ValueError::py_err("invalid key"))
}

/// Mpz bigint to 32bytes big endian
pub fn bigint2bytes(int: &BigInt) -> Result<[u8;32], String> {
    let vec = BigInt::to_vec(int);
    if 32 < vec.len() {
        return Err("too large bigint".to_owned());
    }
    let mut bytes = [0u8;32];
    bytes[(32-vec.len())..].copy_from_slice(&vec);
    Ok(bytes)
}

/// return (is_musig, normal_prefix,)
/// warning: I will add more params
pub fn decode_public_bytes(bytes: &[u8]) -> Result<(bool, u8), ErrorKey> {
    match bytes.get(0) {
        Some(prefix) => {
            if *prefix == 2 || *prefix == 3 || *prefix == 4 {
                Ok((false, *prefix))
            } else if *prefix == 5 || *prefix == 6 || *prefix == 7 {
                Ok((true, *prefix - 3))
            } else {
                Err(ErrorKey::InvalidPublicKey)
            }
        },
        None => Err(ErrorKey::InvalidPublicKey)
    }
}

pub fn pylist2points(list: &PyList) -> PyResult<Vec<GE>> {
    let mut tmp = Vec::new();
    for b in list.into_iter() {
        let b: &PyBytes = b.try_into()?;
        let p = bytes2point(b.as_bytes())?;
        tmp.push(p);
    };
    Ok(tmp)
}

pub fn pylist2bigints(list: &PyList) -> PyResult<Vec<BigInt>> {
    let mut tmp = Vec::with_capacity(list.len());
    for b in list.into_iter() {
        let b: &PyBytes = b.try_into()?;
        let int = BigInt::from(b.as_bytes());
        tmp.push(int);
    };
    Ok(tmp)
}

pub fn pylist2vss(py: Python, t: usize, n: usize, vss_points: &PyList) -> PyResult<Vec<VerifiableSS>> {
    let mut tmp = Vec::with_capacity(vss_points.len());
    for point in vss_points.into_iter() {
        let point: &PyList = match point.try_into() {
            Ok(p) => p,
            Err(_) => {
                let point: &PyTuple = point.try_into()?;
                PyList::new(py, point.as_slice())
            }
        };
        let point = pylist2points(point)?;
        tmp.push(VerifiableSS {
            parameters: ShamirSecretSharing {
                threshold: t,
                share_count: n
            },
            commitments: point
        });
    }
    Ok(tmp)
}
