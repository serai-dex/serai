#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! A modular implementation of FROST for any curve with a ff/group API.
//! Additionally, custom algorithms may be specified so any signature reducible to
//! Schnorr-like may be used with FROST.
//!
//! A Schnorr algorithm is provided, of the form (R, s) where `s = r + cx`, which
//! allows specifying the challenge format. This is intended to easily allow
//! integrating with existing systems.
//!
//! This library offers ciphersuites compatible with the
//! [IETF draft](https://github.com/cfrg/draft-irtf-cfrg-frost). Currently, version
//! 10 is supported.

use core::fmt::{self, Debug};
use std::{
  io::{self, Read, Write},
  sync::Arc,
  collections::HashMap,
};

use thiserror::Error;

use zeroize::{Zeroize, ZeroizeOnDrop};

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

mod schnorr;

/// Curve trait and provided curves/HRAMs, forming various ciphersuites.
pub mod curve;
use curve::Curve;

/// Distributed key generation protocol.
pub mod key_gen;
/// Promote keys between curves.
pub mod promote;

/// Algorithm for the signing process.
pub mod algorithm;
/// Threshold signing protocol.
pub mod sign;

/// Tests for application-provided curves and algorithms.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// (De)serialize a message.
pub trait Serializable: Sized {
  fn read<R: Read>(reader: &mut R, params: FrostParams) -> io::Result<Self>;
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;
}

impl Serializable for () {
  fn read<R: Read>(_: &mut R, _: FrostParams) -> io::Result<Self> {
    Ok(())
  }
  fn write<W: Write>(&self, _: &mut W) -> io::Result<()> {
    Ok(())
  }
}

// Validate a map of serialized values to have the expected included participants
pub(crate) fn validate_map<T>(
  map: &HashMap<u16, T>,
  included: &[u16],
  ours: u16,
) -> Result<(), FrostError> {
  if (map.len() + 1) != included.len() {
    Err(FrostError::InvalidParticipantQuantity(included.len(), map.len() + 1))?;
  }

  for included in included {
    if *included == ours {
      if map.contains_key(included) {
        Err(FrostError::DuplicatedIndex(*included))?;
      }
      continue;
    }

    if !map.contains_key(included) {
      Err(FrostError::MissingParticipant(*included))?;
    }
  }

  Ok(())
}

/// Parameters for a multisig.
// These fields can not be made public as they should be static
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrostParams {
  /// Participants needed to sign on behalf of the group.
  t: u16,
  /// Amount of participants.
  n: u16,
  /// Index of the participant being acted for.
  i: u16,
}

impl FrostParams {
  pub fn new(t: u16, n: u16, i: u16) -> Result<FrostParams, FrostError> {
    if (t == 0) || (n == 0) {
      Err(FrostError::ZeroParameter(t, n))?;
    }

    // When t == n, this shouldn't be used (MuSig2 and other variants of MuSig exist for a reason),
    // but it's not invalid to do so
    if t > n {
      Err(FrostError::InvalidRequiredQuantity(t, n))?;
    }
    if (i == 0) || (i > n) {
      Err(FrostError::InvalidParticipantIndex(n, i))?;
    }

    Ok(FrostParams { t, n, i })
  }

  pub fn t(&self) -> u16 {
    self.t
  }
  pub fn n(&self) -> u16 {
    self.n
  }
  pub fn i(&self) -> u16 {
    self.i
  }
}

/// Various errors possible during key generation/signing.
#[derive(Copy, Clone, Error, Debug)]
pub enum FrostError {
  #[error("a parameter was 0 (required {0}, participants {1})")]
  ZeroParameter(u16, u16),
  #[error("too many participants (max {1}, got {0})")]
  TooManyParticipants(usize, u16),
  #[error("invalid amount of required participants (max {1}, got {0})")]
  InvalidRequiredQuantity(u16, u16),
  #[error("invalid participant index (0 < index <= {0}, yet index is {1})")]
  InvalidParticipantIndex(u16, u16),

  #[error("invalid signing set ({0})")]
  InvalidSigningSet(&'static str),
  #[error("invalid participant quantity (expected {0}, got {1})")]
  InvalidParticipantQuantity(usize, usize),
  #[error("duplicated participant index ({0})")]
  DuplicatedIndex(u16),
  #[error("missing participant {0}")]
  MissingParticipant(u16),
  #[error("invalid commitment (participant {0})")]
  InvalidCommitment(u16),
  #[error("invalid proof of knowledge (participant {0})")]
  InvalidProofOfKnowledge(u16),
  #[error("invalid share (participant {0})")]
  InvalidShare(u16),

  #[error("internal error ({0})")]
  InternalError(&'static str),
}

/// Calculate the lagrange coefficient for a signing set.
pub fn lagrange<F: PrimeField>(i: u16, included: &[u16]) -> F {
  let mut num = F::one();
  let mut denom = F::one();
  for l in included {
    if i == *l {
      continue;
    }

    let share = F::from(u64::try_from(*l).unwrap());
    num *= share;
    denom *= share - F::from(u64::try_from(i).unwrap());
  }

  // Safe as this will only be 0 if we're part of the above loop
  // (which we have an if case to avoid)
  num * denom.invert().unwrap()
}

/// Core keys generated by performing a FROST keygen protocol.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct FrostCore<C: Curve> {
  /// FROST Parameters.
  #[zeroize(skip)]
  params: FrostParams,

  /// Secret share key.
  secret_share: C::F,
  /// Group key.
  group_key: C::G,
  /// Verification shares.
  #[zeroize(skip)]
  verification_shares: HashMap<u16, C::G>,
}

impl<C: Curve> Drop for FrostCore<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for FrostCore<C> {}

impl<C: Curve> Debug for FrostCore<C> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FrostCore")
      .field("params", &self.params)
      .field("group_key", &self.group_key)
      .field("verification_shares", &self.verification_shares)
      .finish()
  }
}

impl<C: Curve> FrostCore<C> {
  pub(crate) fn new(
    params: FrostParams,
    secret_share: C::F,
    verification_shares: HashMap<u16, C::G>,
  ) -> FrostCore<C> {
    #[cfg(debug_assertions)]
    validate_map(&verification_shares, &(0 ..= params.n).collect::<Vec<_>>(), 0).unwrap();

    let t = (1 ..= params.t).collect::<Vec<_>>();
    FrostCore {
      params,
      secret_share,
      group_key: t.iter().map(|i| verification_shares[i] * lagrange::<C::F>(*i, &t)).sum(),
      verification_shares,
    }
  }
  pub fn params(&self) -> FrostParams {
    self.params
  }

  #[cfg(any(test, feature = "tests"))]
  pub(crate) fn secret_share(&self) -> C::F {
    self.secret_share
  }

  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub(crate) fn verification_shares(&self) -> HashMap<u16, C::G> {
    self.verification_shares.clone()
  }

  pub fn serialized_len(n: u16) -> usize {
    8 + C::ID.len() + (3 * 2) + C::F_len() + C::G_len() + (usize::from(n) * C::G_len())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(FrostCore::<C>::serialized_len(self.params.n));
    serialized.extend(u32::try_from(C::ID.len()).unwrap().to_be_bytes());
    serialized.extend(C::ID);
    serialized.extend(self.params.t.to_be_bytes());
    serialized.extend(self.params.n.to_be_bytes());
    serialized.extend(self.params.i.to_be_bytes());
    serialized.extend(self.secret_share.to_repr().as_ref());
    for l in 1 ..= self.params.n {
      serialized.extend(self.verification_shares[&l].to_bytes().as_ref());
    }
    serialized
  }

  pub fn deserialize<R: Read>(cursor: &mut R) -> Result<FrostCore<C>, FrostError> {
    {
      let missing = FrostError::InternalError("FrostCore serialization is missing its curve");
      let different = FrostError::InternalError("deserializing FrostCore for another curve");

      let mut id_len = [0; 4];
      cursor.read_exact(&mut id_len).map_err(|_| missing)?;
      if u32::try_from(C::ID.len()).unwrap().to_be_bytes() != id_len {
        Err(different)?;
      }

      let mut id = vec![0; C::ID.len()];
      cursor.read_exact(&mut id).map_err(|_| missing)?;
      if id != C::ID {
        Err(different)?;
      }
    }

    let (t, n, i) = {
      let mut read_u16 = || {
        let mut value = [0; 2];
        cursor
          .read_exact(&mut value)
          .map_err(|_| FrostError::InternalError("missing participant quantities"))?;
        Ok(u16::from_be_bytes(value))
      };
      (read_u16()?, read_u16()?, read_u16()?)
    };

    let secret_share =
      C::read_F(cursor).map_err(|_| FrostError::InternalError("invalid secret share"))?;

    let mut verification_shares = HashMap::new();
    for l in 1 ..= n {
      verification_shares.insert(
        l,
        C::read_G(cursor).map_err(|_| FrostError::InternalError("invalid verification share"))?,
      );
    }

    Ok(FrostCore::new(
      FrostParams::new(t, n, i).map_err(|_| FrostError::InternalError("invalid parameters"))?,
      secret_share,
      verification_shares,
    ))
  }
}

/// FROST keys usable for signing.
#[derive(Clone, Debug, Zeroize)]
pub struct FrostKeys<C: Curve> {
  /// Core keys.
  #[zeroize(skip)]
  core: Arc<FrostCore<C>>,

  /// Offset applied to these keys.
  pub(crate) offset: Option<C::F>,
}

// Manually implement Drop due to https://github.com/RustCrypto/utils/issues/786
impl<C: Curve> Drop for FrostKeys<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for FrostKeys<C> {}

/// View of keys passed to algorithm implementations.
#[derive(Clone, Zeroize)]
pub struct FrostView<C: Curve> {
  group_key: C::G,
  #[zeroize(skip)]
  included: Vec<u16>,
  secret_share: C::F,
  #[zeroize(skip)]
  verification_shares: HashMap<u16, C::G>,
}

impl<C: Curve> Drop for FrostView<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for FrostView<C> {}

impl<C: Curve> FrostKeys<C> {
  pub fn new(core: FrostCore<C>) -> FrostKeys<C> {
    FrostKeys { core: Arc::new(core), offset: None }
  }

  /// Offset the keys by a given scalar to allow for account and privacy schemes.
  /// This offset is ephemeral and will not be included when these keys are serialized.
  /// Keys offset multiple times will form a new offset of their sum.
  /// Not IETF compliant.
  pub fn offset(&self, offset: C::F) -> FrostKeys<C> {
    let mut res = self.clone();
    // Carry any existing offset
    // Enables schemes like Monero's subaddresses which have a per-subaddress offset and then a
    // one-time-key offset
    res.offset = Some(offset + res.offset.unwrap_or_else(C::F::zero));
    res
  }

  pub fn params(&self) -> FrostParams {
    self.core.params
  }

  pub(crate) fn secret_share(&self) -> C::F {
    self.core.secret_share
  }

  /// Returns the group key with any offset applied.
  pub fn group_key(&self) -> C::G {
    self.core.group_key + (C::generator() * self.offset.unwrap_or_else(C::F::zero))
  }

  /// Returns all participants' verification shares without any offsetting.
  pub(crate) fn verification_shares(&self) -> HashMap<u16, C::G> {
    self.core.verification_shares()
  }

  pub fn serialized_len(n: u16) -> usize {
    FrostCore::<C>::serialized_len(n)
  }

  pub fn serialize(&self) -> Vec<u8> {
    self.core.serialize()
  }

  pub fn view(&self, included: &[u16]) -> Result<FrostView<C>, FrostError> {
    if (included.len() < self.params().t.into()) || (usize::from(self.params().n) < included.len())
    {
      Err(FrostError::InvalidSigningSet("invalid amount of participants included"))?;
    }

    let offset_share = self.offset.unwrap_or_else(C::F::zero) *
      C::F::from(included.len().try_into().unwrap()).invert().unwrap();
    let offset_verification_share = C::generator() * offset_share;

    Ok(FrostView {
      group_key: self.group_key(),
      secret_share: (self.secret_share() * lagrange::<C::F>(self.params().i, included)) +
        offset_share,
      verification_shares: self
        .verification_shares()
        .iter()
        .map(|(l, share)| {
          (*l, (*share * lagrange::<C::F>(*l, included)) + offset_verification_share)
        })
        .collect(),
      included: included.to_vec(),
    })
  }
}

impl<C: Curve> FrostView<C> {
  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub fn included(&self) -> Vec<u16> {
    self.included.clone()
  }

  pub fn secret_share(&self) -> C::F {
    self.secret_share
  }

  pub fn verification_share(&self, l: u16) -> C::G {
    self.verification_shares[&l]
  }
}
