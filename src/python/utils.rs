use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing};
use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt,GE,PK};
use curv::arithmetic::traits::Converter;
use curv::ErrorKey;
use pyo3::prelude::*;
use pyo3::exceptions::ValueError;
use pyo3::types::PyList;


/// Points type
#[derive(PartialEq, Debug)]
pub enum KeyType {
    SingleSig,
    AggregateSig,
    ThresholdSig
}

/// Bitcoin public key format converter
/// compressed key   : 2 or 3 prefix + X
/// uncompressed key : 4 prefix      + X + Y
pub fn bytes2point(bytes: &[u8]) -> PyResult<GE> {
    let len = bytes.len();
    let result = match decode_public_bytes(bytes) {
        Ok((key_type, prefix)) => {
            if len == 33 && (prefix == 2 || prefix == 3) {
                let mut bytes = bytes.to_vec();
                match key_type {
                    KeyType::SingleSig => (),
                    KeyType::AggregateSig => bytes[0] -= 3,
                    KeyType::ThresholdSig => bytes[0] -= 6
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
pub fn decode_public_bytes(bytes: &[u8]) -> Result<(KeyType, u8), ErrorKey> {
    match bytes.get(0) {
        Some(prefix) => {
            if *prefix == 2 || *prefix == 3 || *prefix == 4 {
                Ok((KeyType::SingleSig, *prefix))
            } else if *prefix == 5 || *prefix == 6 || *prefix == 7 {
                Ok((KeyType::AggregateSig, *prefix - 3))
            } else if *prefix == 8 || *prefix == 9 || *prefix == 10 {
                Ok((KeyType::ThresholdSig, *prefix - 6))
            } else {
                Err(ErrorKey::InvalidPublicKey)
            }
        },
        None => Err(ErrorKey::InvalidPublicKey)
    }
}

pub fn pylist2points(list: &PyList) -> PyResult<Vec<GE>> {
    let points: Vec<Vec<u8>> = list.extract()?;
    let mut tmp = Vec::with_capacity(points.len());
    for p in points {
        let p = bytes2point(p.as_slice())?;
        tmp.push(p);
    }
    Ok(tmp)
}

pub fn pylist2bigints(list: &PyList) -> PyResult<Vec<BigInt>> {
    let bigints: Vec<Vec<u8>> = list.extract()?;
    let mut tmp = Vec::with_capacity(bigints.len());
    for int in bigints {
        let int = BigInt::from(int.as_slice());
        tmp.push(int);
    }
    Ok(tmp)
}

pub fn pylist2vss(t: usize, n: usize, vss_points: &PyList) -> PyResult<Vec<VerifiableSS>> {
    let vss_points: Vec<Vec<Vec<u8>>> = vss_points.extract()?;
    let mut result = Vec::with_capacity(vss_points.len());
    for vss in vss_points {
        let mut inner = Vec::with_capacity(vss.len());
        for point in vss {
            let point = bytes2point(point.as_slice())?;
            inner.push(point);
        }
        result.push(VerifiableSS {
            parameters: ShamirSecretSharing {
                threshold: t,
                share_count: n
            },
            commitments: inner
        });
    }
    Ok(result)
}

pub fn option_list2parties_index(_py: Python, n: usize, parties_index: Option<&PyList>)
    -> PyResult<Vec<usize>> {
    let vec = match parties_index {
        Some(list) => {
            if n != list.len() {
                return Err(ValueError::py_err("not correct parties_index length"));
            }
            let tmp: Vec<usize> = list.extract()?;
            tmp
        },
        None => (0..n).collect()
    };
    let vec: Vec<usize> = vec.into_iter().map(|i| i + 1).collect();
    Ok(vec)
}
