use sha3::{Digest, Keccak256};

use group::Group;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, ops::Reduce, sec1::ToEncodedPoint, DecompressPoint},
    AffinePoint, ProjectivePoint, Scalar, U256,
};

use frost::{algorithm::Hram, curve::Secp256k1};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).try_into().unwrap()
}

pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_uint_reduced(U256::from_be_slice(&keccak256(data)))
}

pub fn address(point: &ProjectivePoint) -> [u8; 20] {
    let encoded_point = point.to_encoded_point(false);
    keccak256(&encoded_point.as_ref()[1..65])[12..32]
        .try_into()
        .unwrap()
}

pub fn ecrecover(message: Scalar, v: u8, r: Scalar, s: Scalar) -> Option<[u8; 20]> {
    if r.is_zero().into() || s.is_zero().into() {
        return None;
    }

    #[allow(non_snake_case)]
    let R = AffinePoint::decompress(&r.to_bytes(), v.into());
    #[allow(non_snake_case)]
    if let Some(R) = Option::<AffinePoint>::from(R) {
        #[allow(non_snake_case)]
        let R = ProjectivePoint::from(R);

        let r = r.invert().unwrap();
        let u1 = ProjectivePoint::GENERATOR * (-message * r);
        let u2 = R * (s * r);
        let key: ProjectivePoint = u1 + u2;
        if !bool::from(key.is_identity()) {
            return Some(address(&key));
        }
    }
    return None;
}

#[derive(Clone, Default)]
pub struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
    #[allow(non_snake_case)]
    fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
        let a_encoded_point = A.to_encoded_point(true);
        let mut a_encoded = a_encoded_point.as_ref().to_owned();
        a_encoded[0] += 25; // Ethereum uses 27/28 for point parity
        let mut data = address(R).to_vec();
        data.append(&mut a_encoded);
        data.append(&mut m.to_vec());
        Scalar::from_uint_reduced(U256::from_be_slice(&keccak256(&data)))
    }
}

pub struct ProcessedSignature {
    pub sr: Scalar,
    pub er: Scalar,
    pub px: Scalar,
    pub parity: u8,
    pub message: [u8; 32],
    pub e: Scalar,
}

#[allow(non_snake_case)]
pub fn preprocess_signature(
    m: [u8; 32],
    R: &ProjectivePoint,
    s: Scalar,
    A: &ProjectivePoint,
    chain_id: U256,
) -> (Scalar, Scalar) {
    let processed_sig = preprocess_signature_for_contract(m, R, s, A, chain_id);
    (processed_sig.sr, processed_sig.er)
}

#[allow(non_snake_case)]
pub fn preprocess_signature_for_contract(
    m: [u8; 32],
    R: &ProjectivePoint,
    s: Scalar,
    A: &ProjectivePoint,
    chain_id: U256,
) -> ProcessedSignature {
    let encoded_pk = A.to_encoded_point(true);
    let px = &encoded_pk.as_ref()[1..33];
    let px_scalar = Scalar::from_uint_reduced(U256::from_be_slice(px));
    let e = EthereumHram::hram(R, A, &[chain_id.to_be_byte_array().as_slice(), &m].concat());
    let sr = s.mul(&px_scalar).negate();
    let er = e.mul(&px_scalar).negate();
    ProcessedSignature {
        sr,
        er,
        px: px_scalar,
        parity: &encoded_pk.as_ref()[0] - 2,
        #[allow(non_snake_case)]
        message: m,
        e,
    }
}
