use curv::elliptic::curves::traits::ECPoint;
use curv::{BigInt,FE,GE,PK};
use curv::arithmetic::traits::Converter;
use curv::ErrorKey;

/// Bitcoin public key format converter
/// compressed key   : 2 or 3 prefix + X
/// uncompressed key : 4 prefix      + X + Y
pub fn bytes2point(bytes: &[u8]) -> Result<GE, ErrorKey> {
    let prefix = match bytes.get(0) {
        Some(prefix) => *prefix,
        None => return Err(ErrorKey::InvalidPublicKey)
    };
    let byte_len = bytes.len();
    let public =
        if byte_len == 32 {
            return GE::from_bytes(bytes).map_err(|_err| ErrorKey::InvalidPublicKey);
        }else if byte_len == 33 && (prefix == 2 || prefix == 3) {
            PK::from_slice(bytes).map_err(|_err| ErrorKey::InvalidPublicKey)
        } else if byte_len == 65 && prefix == 4 {
            PK::from_slice(bytes).map_err(|_err| ErrorKey::InvalidPublicKey)
        } else {
            Err(ErrorKey::InvalidPublicKey)
        }?;
    GE::from_bytes(&public.serialize_uncompressed()[1..])
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
