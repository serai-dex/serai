use sha3::{Digest, Keccak256};

use group::ff::PrimeField;
use k256::{
  elliptic_curve::{
    ops::Reduce,
    point::{AffineCoordinates, DecompressPoint},
    sec1::ToEncodedPoint,
  },
  AffinePoint, ProjectivePoint, Scalar, U256 as KU256,
};

use frost::{
  algorithm::{Hram, SchnorrSignature},
  curve::Secp256k1,
};

use ethers_core::{
  types::{Signature as EthersSignature, Transaction},
  utils::rlp::{Rlp, Decodable},
};

use crate::{
  Error, TransactionRequest,
  abi::router::{Signature as AbiSignature},
};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
  <Scalar as Reduce<KU256>>::reduce_bytes(&keccak256(data).into())
}

pub(crate) fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  // Last 20 bytes of the hash of the concatenated x and y coordinates
  // We obtain the concatenated x and y coordinates via the uncompressed encoding of the point
  keccak256(&encoded_point.as_ref()[1 .. 65])[12 ..].try_into().unwrap()
}

pub(crate) fn deterministically_sign(
  chain_id: u64,
  tx: &TransactionRequest,
) -> Result<Transaction, Error> {
  let sig_hash = tx.sighash().0;
  let mut r = hash_to_scalar(&[sig_hash.as_slice(), b"r"].concat());
  let mut s = hash_to_scalar(&[sig_hash.as_slice(), b"s"].concat());
  loop {
    // EIP-155 v
    let v = chain_id
      .checked_mul(2)
      .and_then(|id| id.checked_add(35))
      .ok_or(Error::ChainIdExceedsBounds)?;
    let tx = tx.rlp_signed(&EthersSignature {
      v,
      r: r.to_repr().as_slice().into(),
      s: s.to_repr().as_slice().into(),
    });
    let mut tx = Transaction::decode(&Rlp::new(&tx)).unwrap();
    if tx.recover_from_mut().is_ok() {
      return Ok(tx);
    }

    // Re-hash until valid
    r = hash_to_scalar(r.to_repr().as_ref());
    s = hash_to_scalar(s.to_repr().as_ref());
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

  pub(crate) fn eth_repr(&self) -> [u8; 32] {
    self.px.to_repr().into()
  }

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
    Some(Signature { c, s: signature.s })
  }
}
impl From<&Signature> for AbiSignature {
  fn from(sig: &Signature) -> AbiSignature {
    AbiSignature { c: sig.c.to_repr().into(), s: sig.s.to_repr().into() }
  }
}
