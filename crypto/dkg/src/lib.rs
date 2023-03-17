#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! A collection of implementations of various distributed key generation protocols.
//! They all resolve into the provided Threshold types intended to enable their modularity.
//! Additional utilities around them, such as promotion from one generator to another, are also
//! provided.

use core::{
  fmt::{self, Debug},
  ops::Deref,
};
use std::{io, sync::Arc, collections::HashMap};

use thiserror::Error;

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  Ciphersuite,
};

/// Encryption types and utilities used to secure DKG messages.
pub mod encryption;

/// The distributed key generation protocol described in the
/// [FROST paper](https://eprint.iacr.org/2020/852).
pub mod frost;

/// Promote keys between ciphersuites.
pub mod promote;

/// Tests for application-provided curves and algorithms.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// The ID of a participant, defined as a non-zero u16.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Participant(pub(crate) u16);
impl Participant {
  pub fn new(i: u16) -> Option<Participant> {
    if i == 0 {
      None
    } else {
      Some(Participant(i))
    }
  }

  #[allow(clippy::wrong_self_convention)]
  pub fn to_bytes(&self) -> [u8; 2] {
    self.0.to_le_bytes()
  }
}

impl From<Participant> for u16 {
  fn from(participant: Participant) -> u16 {
    participant.0
  }
}

impl fmt::Display for Participant {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// Various errors possible during key generation/signing.
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum DkgError<B: Clone + PartialEq + Eq + Debug> {
  #[error("a parameter was 0 (threshold {0}, participants {1})")]
  ZeroParameter(u16, u16),
  #[error("invalid amount of required participants (max {1}, got {0})")]
  InvalidRequiredQuantity(u16, u16),
  #[error("invalid participant (0 < participant <= {0}, yet participant is {1})")]
  InvalidParticipant(u16, Participant),

  #[error("invalid signing set")]
  InvalidSigningSet,
  #[error("invalid participant quantity (expected {0}, got {1})")]
  InvalidParticipantQuantity(usize, usize),
  #[error("duplicated participant ({0})")]
  DuplicatedParticipant(Participant),
  #[error("missing participant {0}")]
  MissingParticipant(Participant),

  #[error("invalid proof of knowledge (participant {0})")]
  InvalidProofOfKnowledge(Participant),
  #[error("invalid share (participant {participant}, blame {blame})")]
  InvalidShare { participant: Participant, blame: Option<B> },

  #[error("internal error ({0})")]
  InternalError(&'static str),
}

// Validate a map of values to have the expected included participants
pub(crate) fn validate_map<T, B: Clone + PartialEq + Eq + Debug>(
  map: &HashMap<Participant, T>,
  included: &[Participant],
  ours: Participant,
) -> Result<(), DkgError<B>> {
  if (map.len() + 1) != included.len() {
    Err(DkgError::InvalidParticipantQuantity(included.len(), map.len() + 1))?;
  }

  for included in included {
    if *included == ours {
      if map.contains_key(included) {
        Err(DkgError::DuplicatedParticipant(*included))?;
      }
      continue;
    }

    if !map.contains_key(included) {
      Err(DkgError::MissingParticipant(*included))?;
    }
  }

  Ok(())
}

/// Parameters for a multisig.
// These fields should not be made public as they should be static
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ThresholdParams {
  /// Participants needed to sign on behalf of the group.
  t: u16,
  /// Amount of participants.
  n: u16,
  /// Index of the participant being acted for.
  i: Participant,
}

impl ThresholdParams {
  pub fn new(t: u16, n: u16, i: Participant) -> Result<ThresholdParams, DkgError<()>> {
    if (t == 0) || (n == 0) {
      Err(DkgError::ZeroParameter(t, n))?;
    }

    // When t == n, this shouldn't be used (MuSig2 and other variants of MuSig exist for a reason),
    // but it's not invalid to do so
    if t > n {
      Err(DkgError::InvalidRequiredQuantity(t, n))?;
    }
    if u16::from(i) > n {
      Err(DkgError::InvalidParticipant(n, i))?;
    }

    Ok(ThresholdParams { t, n, i })
  }

  pub fn t(&self) -> u16 {
    self.t
  }
  pub fn n(&self) -> u16 {
    self.n
  }
  pub fn i(&self) -> Participant {
    self.i
  }
}

/// Calculate the lagrange coefficient for a signing set.
pub fn lagrange<F: PrimeField>(i: Participant, included: &[Participant]) -> F {
  let i_f = F::from(u64::from(u16::from(i)));

  let mut num = F::one();
  let mut denom = F::one();
  for l in included {
    if i == *l {
      continue;
    }

    let share = F::from(u64::from(u16::from(*l)));
    num *= share;
    denom *= share - i_f;
  }

  // Safe as this will only be 0 if we're part of the above loop
  // (which we have an if case to avoid)
  num * denom.invert().unwrap()
}

/// Keys and verification shares generated by a DKG.
/// Called core as they're expected to be wrapped into an Arc before usage in various operations.
#[derive(Clone, PartialEq, Eq)]
pub struct ThresholdCore<C: Ciphersuite> {
  /// Threshold Parameters.
  params: ThresholdParams,

  /// Secret share key.
  secret_share: Zeroizing<C::F>,
  /// Group key.
  group_key: C::G,
  /// Verification shares.
  verification_shares: HashMap<Participant, C::G>,
}

impl<C: Ciphersuite> fmt::Debug for ThresholdCore<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ThresholdCore")
      .field("params", &self.params)
      .field("group_key", &self.group_key)
      .field("verification_shares", &self.verification_shares)
      .finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> Zeroize for ThresholdCore<C> {
  fn zeroize(&mut self) {
    self.params.zeroize();
    self.secret_share.zeroize();
    self.group_key.zeroize();
    for (_, share) in self.verification_shares.iter_mut() {
      share.zeroize();
    }
  }
}

impl<C: Ciphersuite> ThresholdCore<C> {
  pub(crate) fn new(
    params: ThresholdParams,
    secret_share: Zeroizing<C::F>,
    verification_shares: HashMap<Participant, C::G>,
  ) -> ThresholdCore<C> {
    let t = (1 ..= params.t).map(Participant).collect::<Vec<_>>();
    ThresholdCore {
      params,
      secret_share,
      group_key: t.iter().map(|i| verification_shares[i] * lagrange::<C::F>(*i, &t)).sum(),
      verification_shares,
    }
  }
  pub fn params(&self) -> ThresholdParams {
    self.params
  }

  pub fn secret_share(&self) -> &Zeroizing<C::F> {
    &self.secret_share
  }

  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub(crate) fn verification_shares(&self) -> HashMap<Participant, C::G> {
    self.verification_shares.clone()
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(C::ID.len()).unwrap().to_le_bytes())?;
    writer.write_all(C::ID)?;
    writer.write_all(&self.params.t.to_le_bytes())?;
    writer.write_all(&self.params.n.to_le_bytes())?;
    writer.write_all(&self.params.i.to_bytes())?;
    let mut share_bytes = self.secret_share.to_repr();
    writer.write_all(share_bytes.as_ref())?;
    share_bytes.as_mut().zeroize();
    for l in 1 ..= self.params.n {
      writer
        .write_all(self.verification_shares[&Participant::new(l).unwrap()].to_bytes().as_ref())?;
    }
    Ok(())
  }

  pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
    let mut serialized = Zeroizing::new(vec![]);
    self.write::<Vec<u8>>(serialized.as_mut()).unwrap();
    serialized
  }

  pub fn read<R: io::Read>(reader: &mut R) -> Result<ThresholdCore<C>, DkgError<()>> {
    {
      let missing = DkgError::InternalError("ThresholdCore serialization is missing its curve");
      let different = DkgError::InternalError("deserializing ThresholdCore for another curve");

      let mut id_len = [0; 4];
      reader.read_exact(&mut id_len).map_err(|_| missing.clone())?;
      if u32::try_from(C::ID.len()).unwrap().to_le_bytes() != id_len {
        Err(different.clone())?;
      }

      let mut id = vec![0; C::ID.len()];
      reader.read_exact(&mut id).map_err(|_| missing)?;
      if id != C::ID {
        Err(different)?;
      }
    }

    let (t, n, i) = {
      let mut read_u16 = || {
        let mut value = [0; 2];
        reader
          .read_exact(&mut value)
          .map_err(|_| DkgError::InternalError("missing participant quantities"))?;
        Ok(u16::from_le_bytes(value))
      };
      (
        read_u16()?,
        read_u16()?,
        Participant::new(read_u16()?)
          .ok_or(DkgError::InternalError("invalid participant index"))?,
      )
    };

    let secret_share = Zeroizing::new(
      C::read_F(reader).map_err(|_| DkgError::InternalError("invalid secret share"))?,
    );

    let mut verification_shares = HashMap::new();
    for l in (1 ..= n).map(Participant) {
      verification_shares.insert(
        l,
        <C as Ciphersuite>::read_G(reader)
          .map_err(|_| DkgError::InternalError("invalid verification share"))?,
      );
    }

    Ok(ThresholdCore::new(
      ThresholdParams::new(t, n, i).map_err(|_| DkgError::InternalError("invalid parameters"))?,
      secret_share,
      verification_shares,
    ))
  }
}

/// Threshold keys usable for signing.
#[derive(Clone, Debug, Zeroize)]
pub struct ThresholdKeys<C: Ciphersuite> {
  // Core keys.
  // If this is the last reference, the underlying keys will be dropped. When that happens, the
  // private key present within it will be zeroed out (as it's within Zeroizing).
  #[zeroize(skip)]
  core: Arc<ThresholdCore<C>>,

  // Offset applied to these keys.
  pub(crate) offset: Option<C::F>,
}

/// View of keys passed to algorithm implementations.
#[derive(Clone)]
pub struct ThresholdView<C: Ciphersuite> {
  offset: C::F,
  group_key: C::G,
  included: Vec<Participant>,
  secret_share: Zeroizing<C::F>,
  original_verification_shares: HashMap<Participant, C::G>,
  verification_shares: HashMap<Participant, C::G>,
}

impl<C: Ciphersuite> fmt::Debug for ThresholdView<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ThresholdView")
      .field("offset", &self.offset)
      .field("group_key", &self.group_key)
      .field("included", &self.included)
      .field("original_verification_shares", &self.original_verification_shares)
      .field("verification_shares", &self.verification_shares)
      .finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> Zeroize for ThresholdView<C> {
  fn zeroize(&mut self) {
    self.offset.zeroize();
    self.group_key.zeroize();
    self.included.zeroize();
    self.secret_share.zeroize();
    for (_, share) in self.original_verification_shares.iter_mut() {
      share.zeroize();
    }
    for (_, share) in self.verification_shares.iter_mut() {
      share.zeroize();
    }
  }
}

impl<C: Ciphersuite> ThresholdKeys<C> {
  pub fn new(core: ThresholdCore<C>) -> ThresholdKeys<C> {
    ThresholdKeys { core: Arc::new(core), offset: None }
  }

  /// Offset the keys by a given scalar to allow for account and privacy schemes.
  /// This offset is ephemeral and will not be included when these keys are serialized.
  /// Keys offset multiple times will form a new offset of their sum.
  #[must_use]
  pub fn offset(&self, offset: C::F) -> ThresholdKeys<C> {
    let mut res = self.clone();
    // Carry any existing offset
    // Enables schemes like Monero's subaddresses which have a per-subaddress offset and then a
    // one-time-key offset
    res.offset = Some(offset + res.offset.unwrap_or_else(C::F::zero));
    res
  }

  /// Returns the current offset in-use for these keys.
  pub fn current_offset(&self) -> Option<C::F> {
    self.offset
  }

  pub fn params(&self) -> ThresholdParams {
    self.core.params
  }

  pub fn secret_share(&self) -> &Zeroizing<C::F> {
    &self.core.secret_share
  }

  /// Returns the group key with any offset applied.
  pub fn group_key(&self) -> C::G {
    self.core.group_key + (C::generator() * self.offset.unwrap_or_else(C::F::zero))
  }

  /// Returns all participants' verification shares without any offsetting.
  pub(crate) fn verification_shares(&self) -> HashMap<Participant, C::G> {
    self.core.verification_shares()
  }

  pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
    self.core.serialize()
  }

  pub fn view(&self, mut included: Vec<Participant>) -> Result<ThresholdView<C>, DkgError<()>> {
    if (included.len() < self.params().t.into()) || (usize::from(self.params().n) < included.len())
    {
      Err(DkgError::InvalidSigningSet)?;
    }
    included.sort();

    let mut secret_share =
      Zeroizing::new(lagrange::<C::F>(self.params().i, &included) * self.secret_share().deref());

    let mut verification_shares = self.verification_shares();
    for (i, share) in verification_shares.iter_mut() {
      *share *= lagrange::<C::F>(*i, &included);
    }

    // The offset is included by adding it to the participant with the lowest ID
    let offset = self.offset.unwrap_or_else(C::F::zero);
    if included[0] == self.params().i() {
      *secret_share += offset;
    }
    *verification_shares.get_mut(&included[0]).unwrap() += C::generator() * offset;

    Ok(ThresholdView {
      offset,
      group_key: self.group_key(),
      secret_share,
      original_verification_shares: self.verification_shares(),
      verification_shares,
      included,
    })
  }
}

impl<C: Ciphersuite> ThresholdView<C> {
  pub fn offset(&self) -> C::F {
    self.offset
  }

  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub fn included(&self) -> &[Participant] {
    &self.included
  }

  pub fn secret_share(&self) -> &Zeroizing<C::F> {
    &self.secret_share
  }

  pub fn original_verification_share(&self, l: Participant) -> C::G {
    self.original_verification_shares[&l]
  }

  pub fn verification_share(&self, l: Participant) -> C::G {
    self.verification_shares[&l]
  }
}
