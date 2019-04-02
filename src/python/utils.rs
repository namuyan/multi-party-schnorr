use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt,FE,GE,PK};
use curv::arithmetic::traits::Converter;
use curv::ErrorKey;

/// Bitcoin public key format converter
/// compressed key   : 2 or 3 prefix + X
/// uncompressed key : 4 prefix      + X + Y
pub fn bytes2point(bytes: &[u8]) -> Result<GE, ErrorKey> {
    let len = bytes.len();
    match decode_public_bytes(bytes) {
        Ok((is_musig, prefix)) => {
            if len == 33 && (prefix == 2 || prefix == 3) {
                let mut bytes = bytes.to_vec();
                if is_musig {
                    bytes[0] -= 3;
                }
                let public = PK::from_slice(&bytes)
                    .map_err(|_| ErrorKey::InvalidPublicKey)?;
                GE::from_bytes(&public.serialize_uncompressed()[1..])
            }else if len == 65 && prefix == 4 {
                GE::from_bytes(&bytes[1..])
            } else {
                Err(ErrorKey::InvalidPublicKey)
            }
        },
        Err(err) => Err(err)
    }
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
