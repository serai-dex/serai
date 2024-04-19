use group::ff::PrimeField;
use k256::{
  elliptic_curve::{ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint},
  ProjectivePoint, Scalar, U256 as KU256,
};
#[cfg(test)]
use k256::{elliptic_curve::point::DecompressPoint, AffinePoint};

use frost::{
  algorithm::{Hram, SchnorrSignature},
  curve::{Ciphersuite, Secp256k1},
};

use alloy_core::primitives::{Parity, Signature as AlloySignature};
use alloy_consensus::{SignableTransaction, Signed, TxLegacy};

use crate::abi::router::{Signature as AbiSignature};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
  alloy_core::primitives::keccak256(data).into()
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  <Scalar as Reduce<KU256>>::reduce_bytes(&keccak256(data).into())
}

pub fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  // Last 20 bytes of the hash of the concatenated x and y coordinates
  // We obtain the concatenated x and y coordinates via the uncompressed encoding of the point
  keccak256(&encoded_point.as_ref()[1 .. 65])[12 ..].try_into().unwrap()
}

pub(crate) fn deterministically_sign(tx: &TxLegacy) -> Signed<TxLegacy> {
  assert!(
    tx.chain_id.is_none(),
    "chain ID was Some when deterministically signing a TX (causing a non-deterministic signer)"
  );

  let sig_hash = tx.signature_hash().0;
  let mut r = hash_to_scalar(&[sig_hash.as_slice(), b"r"].concat());
  let mut s = hash_to_scalar(&[sig_hash.as_slice(), b"s"].concat());
  loop {
    let r_bytes: [u8; 32] = r.to_repr().into();
    let s_bytes: [u8; 32] = s.to_repr().into();
    let v = Parity::NonEip155(false);
    let signature =
      AlloySignature::from_scalars_and_parity(r_bytes.into(), s_bytes.into(), v).unwrap();
    let tx = tx.clone().into_signed(signature);
    if tx.recover_signer().is_ok() {
      return tx;
    }

    // Re-hash until valid
    r = hash_to_scalar(r_bytes.as_ref());
    s = hash_to_scalar(s_bytes.as_ref());
  }
}

/// The public key for a Schnorr-signing account.
#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey {
  pub(crate) A: ProjectivePoint,
  pub(crate) px: Scalar,
}

impl PublicKey {
  /// Construct a new `PublicKey`.
  ///
  /// This will return None if the provided point isn't eligible to be a public key (due to
  /// bounds such as parity).
  #[allow(non_snake_case)]
  pub fn new(A: ProjectivePoint) -> Option<PublicKey> {
    let affine = A.to_affine();
    // Only allow even keys to save a word within Ethereum
    let is_odd = bool::from(affine.y_is_odd());
    if is_odd {
      None?;
    }

    let x_coord = affine.x();
    let x_coord_scalar = <Scalar as Reduce<KU256>>::reduce_bytes(&x_coord);
    // Return None if a reduction would occur
    // Reductions would be incredibly unlikely and shouldn't be an issue, yet it's one less
    // headache/concern to have
    // This does ban a trivial amoount of public keys
    if x_coord_scalar.to_repr() != x_coord {
      None?;
    }

    Some(PublicKey { A, px: x_coord_scalar })
  }

  pub fn point(&self) -> ProjectivePoint {
    self.A
  }

  pub(crate) fn eth_repr(&self) -> [u8; 32] {
    self.px.to_repr().into()
  }

  #[cfg(test)]
  pub(crate) fn from_eth_repr(repr: [u8; 32]) -> Option<Self> {
    #[allow(non_snake_case)]
    let A = Option::<AffinePoint>::from(AffinePoint::decompress(&repr.into(), 0.into()))?.into();
    Option::from(Scalar::from_repr(repr.into())).map(|px| PublicKey { A, px })
  }
}

/// The HRAm to use for the Schnorr contract.
#[derive(Clone, Default)]
pub struct EthereumHram {}
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    let x_coord = A.to_affine().x();

    let mut data = address(R).to_vec();
    data.extend(x_coord.as_slice());
    data.extend(m);

    <Scalar as Reduce<KU256>>::reduce_bytes(&keccak256(&data).into())
  }
}

/// A signature for the Schnorr contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
  pub(crate) c: Scalar,
  pub(crate) s: Scalar,
}
impl Signature {
  pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> bool {
    #[allow(non_snake_case)]
    let R = (Secp256k1::generator() * self.s) - (public_key.A * self.c);
    EthereumHram::hram(&R, &public_key.A, message) == self.c
  }

  /// Construct a new `Signature`.
  ///
  /// This will return None if the signature is invalid.
  pub fn new(
    public_key: &PublicKey,
    message: &[u8],
    signature: SchnorrSignature<Secp256k1>,
  ) -> Option<Signature> {
    let c = EthereumHram::hram(&signature.R, &public_key.A, message);
    if !signature.verify(public_key.A, c) {
      None?;
    }

    let res = Signature { c, s: signature.s };
    assert!(res.verify(public_key, message));
    Some(res)
  }

  pub fn c(&self) -> Scalar {
    self.c
  }
  pub fn s(&self) -> Scalar {
    self.s
  }

  pub fn to_bytes(&self) -> [u8; 64] {
    let mut res = [0; 64];
    res[.. 32].copy_from_slice(self.c.to_repr().as_ref());
    res[32 ..].copy_from_slice(self.s.to_repr().as_ref());
    res
  }

  pub fn from_bytes(bytes: [u8; 64]) -> std::io::Result<Self> {
    let mut reader = bytes.as_slice();
    let c = Secp256k1::read_F(&mut reader)?;
    let s = Secp256k1::read_F(&mut reader)?;
    Ok(Signature { c, s })
  }
}
impl From<&Signature> for AbiSignature {
  fn from(sig: &Signature) -> AbiSignature {
    let c: [u8; 32] = sig.c.to_repr().into();
    let s: [u8; 32] = sig.s.to_repr().into();
    AbiSignature { c: c.into(), s: s.into() }
  }
}
