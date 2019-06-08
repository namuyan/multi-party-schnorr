use python::pythreshold::verify_threshold_signature;
use python::pyagg::verify_aggregate_signature;
use python::pyo3utils::{decode_public_bytes, KeyType, bytes2point_inner};
use curv::elliptic::curves::traits::{ECScalar};
use curv::BigInt;


#[inline]
pub fn verify_auto_signature(s: &[u8], r: &[u8], apk: &[u8], message: &[u8])
    -> Result<bool, String> {
    let is_verify = match decode_public_bytes(apk) {
        Ok((key_type, _prefix)) => match key_type {
            KeyType::SingleSig | KeyType::AggregateSig => {
                let signature = BigInt::from(s);
                let r_x = BigInt::from(r);
                let apk = bytes2point_inner(apk)?;
                let is_musig = key_type == KeyType::AggregateSig;
                verify_aggregate_signature(&signature, &r_x, &apk, message, is_musig).is_ok()
            },
            KeyType::ThresholdSig => {
                let sigma = ECScalar::from(&BigInt::from(s));
                let Y = bytes2point_inner(apk)?;
                let V = bytes2point_inner(r)?;
                verify_threshold_signature(sigma, &Y, &V, message)
            }
        },
        Err(_) => return Err("decode public point failed".to_string())
    };
    Ok(is_verify)
}
