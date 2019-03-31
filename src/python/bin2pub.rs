use curv::elliptic::curves::secp256_k1::{PK,Secp256k1Point};
use curv::elliptic::curves::traits::ECPoint;
use curv::ErrorKey;

/// Bitcoin public key format converter
/// compressed key   : 2 or 3 prefix + X
/// uncompressed key : 4 prefix      + X + Y
pub fn public_from_bytes(bytes: &[u8]) -> Result<Secp256k1Point, ErrorKey> {
    if bytes.len() < 32 {
        return Err(ErrorKey::InvalidPublicKey);
    }
    let prefix = bytes[0];
    let byte_len = bytes.len();

    let public =
        if byte_len == 33 && (prefix == 2 || prefix == 3) {
            PK::from_slice(bytes).map_err(|_err| ErrorKey::InvalidPublicKey)
        } else if byte_len == 65 && prefix == 4 {
            PK::from_slice(bytes).map_err(|_err| ErrorKey::InvalidPublicKey)
        } else {
            Err(ErrorKey::InvalidPublicKey)
        }?;
    Secp256k1Point::from_bytes(&public.serialize_uncompressed()[1..])
}
