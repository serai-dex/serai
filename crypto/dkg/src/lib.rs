#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::{self, Debug};

#[cfg(feature = "std")]
use thiserror::Error;

use zeroize::Zeroize;

/// MuSig-style key aggregation.
pub mod musig;

/// Encryption types and utilities used to secure DKG messages.
#[cfg(feature = "std")]
pub mod encryption;

/// The PedPoP distributed key generation protocol described in the
/// [FROST paper](https://eprint.iacr.org/2020/852), augmented to be verifiable.
#[cfg(feature = "std")]
pub mod pedpop;

/// The one-round DKG described in the [eVRF paper](https://eprint.iacr.org/2024/397).
#[cfg(all(feature = "std", feature = "evrf"))]
pub mod evrf;

/// Promote keys between ciphersuites.
#[cfg(feature = "std")]
pub mod promote;

/// Tests for application-provided curves and algorithms.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// The ID of a participant, defined as a non-zero u16.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
pub struct Participant(pub(crate) u16);
impl Participant {
  /// Create a new Participant identifier from a u16.
  pub fn new(i: u16) -> Option<Participant> {
    if i == 0 {
      None
    } else {
      Some(Participant(i))
    }
  }

  /// Convert a Participant identifier to bytes.
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

/// Various errors possible during key generation.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum DkgError<B: Clone + PartialEq + Eq + Debug> {
  /// A parameter was zero.
  #[cfg_attr(feature = "std", error("a parameter was 0 (threshold {0}, participants {1})"))]
  ZeroParameter(u16, u16),
  /// The threshold exceeded the amount of participants.
  #[cfg_attr(feature = "std", error("invalid threshold (max {1}, got {0})"))]
  InvalidThreshold(u16, u16),
  /// Invalid participant identifier.
  #[cfg_attr(
    feature = "std",
    error("invalid participant (0 < participant <= {0}, yet participant is {1})")
  )]
  InvalidParticipant(u16, Participant),

  /// Invalid signing set.
  #[cfg_attr(feature = "std", error("invalid signing set"))]
  InvalidSigningSet,
  /// Invalid amount of participants.
  #[cfg_attr(feature = "std", error("invalid participant quantity (expected {0}, got {1})"))]
  InvalidParticipantQuantity(usize, usize),
  /// A participant was duplicated.
  #[cfg_attr(feature = "std", error("duplicated participant ({0})"))]
  DuplicatedParticipant(Participant),
  /// A participant was missing.
  #[cfg_attr(feature = "std", error("missing participant {0}"))]
  MissingParticipant(Participant),

  /// An invalid proof of knowledge was provided.
  #[cfg_attr(feature = "std", error("invalid proof of knowledge (participant {0})"))]
  InvalidCommitments(Participant),
  /// An invalid DKG share was provided.
  #[cfg_attr(feature = "std", error("invalid share (participant {participant}, blame {blame})"))]
  InvalidShare { participant: Participant, blame: Option<B> },
}

#[cfg(feature = "std")]
mod lib {
  pub use super::*;

  use core::ops::Deref;
  use std::{io, sync::Arc, collections::HashMap};

  use zeroize::Zeroizing;

  use ciphersuite::{
    group::{
      ff::{Field, PrimeField},
      GroupEncoding,
    },
    Ciphersuite,
  };

  #[cfg(feature = "borsh")]
  impl borsh::BorshDeserialize for Participant {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
      Participant::new(u16::deserialize_reader(reader)?)
        .ok_or_else(|| io::Error::other("invalid participant"))
    }
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
  #[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
  pub struct ThresholdParams {
    /// Participants needed to sign on behalf of the group.
    pub(crate) t: u16,
    /// Amount of participants.
    pub(crate) n: u16,
    /// Index of the participant being acted for.
    pub(crate) i: Participant,
  }

  impl ThresholdParams {
    /// Create a new set of parameters.
    pub fn new(t: u16, n: u16, i: Participant) -> Result<ThresholdParams, DkgError<()>> {
      if (t == 0) || (n == 0) {
        Err(DkgError::ZeroParameter(t, n))?;
      }

      if t > n {
        Err(DkgError::InvalidThreshold(t, n))?;
      }
      if u16::from(i) > n {
        Err(DkgError::InvalidParticipant(n, i))?;
      }

      Ok(ThresholdParams { t, n, i })
    }

    /// Return the threshold for a multisig with these parameters.
    pub fn t(&self) -> u16 {
      self.t
    }
    /// Return the amount of participants for a multisig with these parameters.
    pub fn n(&self) -> u16 {
      self.n
    }
    /// Return the participant index of the share with these parameters.
    pub fn i(&self) -> Participant {
      self.i
    }
  }

  #[cfg(feature = "borsh")]
  impl borsh::BorshDeserialize for ThresholdParams {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
      let t = u16::deserialize_reader(reader)?;
      let n = u16::deserialize_reader(reader)?;
      let i = Participant::deserialize_reader(reader)?;
      ThresholdParams::new(t, n, i).map_err(|e| io::Error::other(format!("{e:?}")))
    }
  }

  #[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
  #[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
  pub(crate) enum Interpolation {
    None,
    Lagrange,
  }

  impl Interpolation {
    pub(crate) fn interpolation_factor<F: PrimeField>(
      self,
      i: Participant,
      included: &[Participant],
    ) -> F {
      match self {
        Interpolation::None => F::ONE,
        Interpolation::Lagrange => {
          let i_f = F::from(u64::from(u16::from(i)));

          let mut num = F::ONE;
          let mut denom = F::ONE;
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
      }
    }
  }

  /// Keys and verification shares generated by a DKG.
  /// Called core as they're expected to be wrapped into an Arc before usage in various operations.
  #[derive(Clone, PartialEq, Eq)]
  pub struct ThresholdCore<C: Ciphersuite> {
    /// Threshold Parameters.
    pub(crate) params: ThresholdParams,
    /// The interpolation method used.
    pub(crate) interpolation: Interpolation,

    /// Secret share key.
    pub(crate) secret_share: Zeroizing<C::F>,
    /// Group key.
    pub(crate) group_key: C::G,
    /// Verification shares.
    pub(crate) verification_shares: HashMap<Participant, C::G>,
  }

  impl<C: Ciphersuite> fmt::Debug for ThresholdCore<C> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
      fmt
        .debug_struct("ThresholdCore")
        .field("params", &self.params)
        .field("interpolation", &self.interpolation)
        .field("group_key", &self.group_key)
        .field("verification_shares", &self.verification_shares)
        .finish_non_exhaustive()
    }
  }

  impl<C: Ciphersuite> Zeroize for ThresholdCore<C> {
    fn zeroize(&mut self) {
      self.params.zeroize();
      self.interpolation.zeroize();
      self.secret_share.zeroize();
      self.group_key.zeroize();
      for share in self.verification_shares.values_mut() {
        share.zeroize();
      }
    }
  }

  impl<C: Ciphersuite> ThresholdCore<C> {
    pub(crate) fn new(
      params: ThresholdParams,
      interpolation: Interpolation,
      secret_share: Zeroizing<C::F>,
      verification_shares: HashMap<Participant, C::G>,
    ) -> ThresholdCore<C> {
      let t = (1 ..= params.t()).map(Participant).collect::<Vec<_>>();
      ThresholdCore {
        params,
        interpolation,
        secret_share,
        group_key: t
          .iter()
          .map(|i| verification_shares[i] * interpolation.interpolation_factor::<C::F>(*i, &t))
          .sum(),
        verification_shares,
      }
    }

    /// Parameters for these keys.
    pub fn params(&self) -> ThresholdParams {
      self.params
    }

    /// Secret share for these keys.
    pub fn secret_share(&self) -> &Zeroizing<C::F> {
      &self.secret_share
    }

    /// Group key for these keys.
    pub fn group_key(&self) -> C::G {
      self.group_key
    }

    pub(crate) fn verification_shares(&self) -> HashMap<Participant, C::G> {
      self.verification_shares.clone()
    }

    /// Write these keys to a type satisfying std::io::Write.
    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
      writer.write_all(&u32::try_from(C::ID.len()).unwrap().to_le_bytes())?;
      writer.write_all(C::ID)?;
      writer.write_all(&self.params.t.to_le_bytes())?;
      writer.write_all(&self.params.n.to_le_bytes())?;
      writer.write_all(&self.params.i.to_bytes())?;
      writer.write_all(match self.interpolation {
        Interpolation::None => &[0],
        Interpolation::Lagrange => &[1],
      })?;
      let mut share_bytes = self.secret_share.to_repr();
      writer.write_all(share_bytes.as_ref())?;
      share_bytes.as_mut().zeroize();
      for l in 1 ..= self.params.n {
        writer
          .write_all(self.verification_shares[&Participant::new(l).unwrap()].to_bytes().as_ref())?;
      }
      Ok(())
    }

    /// Serialize these keys to a `Vec<u8>`.
    pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
      let mut serialized = Zeroizing::new(vec![]);
      self.write::<Vec<u8>>(serialized.as_mut()).unwrap();
      serialized
    }

    /// Read keys from a type satisfying std::io::Read.
    pub fn read<R: io::Read>(reader: &mut R) -> io::Result<ThresholdCore<C>> {
      {
        let different = || io::Error::other("deserializing ThresholdCore for another curve");

        let mut id_len = [0; 4];
        reader.read_exact(&mut id_len)?;
        if u32::try_from(C::ID.len()).unwrap().to_le_bytes() != id_len {
          Err(different())?;
        }

        let mut id = vec![0; C::ID.len()];
        reader.read_exact(&mut id)?;
        if id != C::ID {
          Err(different())?;
        }
      }

      let (t, n, i) = {
        let mut read_u16 = || -> io::Result<u16> {
          let mut value = [0; 2];
          reader.read_exact(&mut value)?;
          Ok(u16::from_le_bytes(value))
        };
        (
          read_u16()?,
          read_u16()?,
          Participant::new(read_u16()?).ok_or(io::Error::other("invalid participant index"))?,
        )
      };

      let mut interpolation = [0];
      reader.read_exact(&mut interpolation)?;
      let interpolation = match interpolation[0] {
        0 => Interpolation::None,
        1 => Interpolation::Lagrange,
        _ => Err(io::Error::other("invalid interpolation method"))?,
      };

      let secret_share = Zeroizing::new(C::read_F(reader)?);

      let mut verification_shares = HashMap::new();
      for l in (1 ..= n).map(Participant) {
        verification_shares.insert(l, <C as Ciphersuite>::read_G(reader)?);
      }

      Ok(ThresholdCore::new(
        ThresholdParams::new(t, n, i).map_err(|_| io::Error::other("invalid parameters"))?,
        interpolation,
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
    pub(crate) core: Arc<ThresholdCore<C>>,

    // Offset applied to these keys.
    pub(crate) offset: Option<C::F>,
  }

  /// View of keys, interpolated and offset for usage.
  #[derive(Clone)]
  pub struct ThresholdView<C: Ciphersuite> {
    interpolation: Interpolation,
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
        .field("interpolation", &self.interpolation)
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
      for share in self.original_verification_shares.values_mut() {
        share.zeroize();
      }
      for share in self.verification_shares.values_mut() {
        share.zeroize();
      }
    }
  }

  impl<C: Ciphersuite> ThresholdKeys<C> {
    /// Create a new set of ThresholdKeys from a ThresholdCore.
    pub fn new(core: ThresholdCore<C>) -> ThresholdKeys<C> {
      ThresholdKeys { core: Arc::new(core), offset: None }
    }

    /// Offset the keys by a given scalar to allow for various account and privacy schemes.
    ///
    /// This offset is ephemeral and will not be included when these keys are serialized. It also
    /// accumulates, so calling offset multiple times will produce a offset of the offsets' sum.
    #[must_use]
    pub fn offset(&self, offset: C::F) -> ThresholdKeys<C> {
      let mut res = self.clone();
      // Carry any existing offset
      // Enables schemes like Monero's subaddresses which have a per-subaddress offset and then a
      // one-time-key offset
      res.offset = Some(offset + res.offset.unwrap_or(C::F::ZERO));
      res
    }

    /// Return the current offset in-use for these keys.
    pub fn current_offset(&self) -> Option<C::F> {
      self.offset
    }

    /// Return the parameters for these keys.
    pub fn params(&self) -> ThresholdParams {
      self.core.params
    }

    /// Return the secret share for these keys.
    pub fn secret_share(&self) -> &Zeroizing<C::F> {
      &self.core.secret_share
    }

    /// Return the group key, with any offset applied.
    pub fn group_key(&self) -> C::G {
      self.core.group_key + (C::generator() * self.offset.unwrap_or(C::F::ZERO))
    }

    /// Return all participants' verification shares without any offsetting.
    pub(crate) fn verification_shares(&self) -> HashMap<Participant, C::G> {
      self.core.verification_shares()
    }

    /// Serialize these keys to a `Vec<u8>`.
    pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
      self.core.serialize()
    }

    /// Obtain a view of these keys, with any offset applied, interpolated for the specified signing
    /// set.
    pub fn view(&self, mut included: Vec<Participant>) -> Result<ThresholdView<C>, DkgError<()>> {
      if (included.len() < self.params().t.into()) ||
        (usize::from(self.params().n()) < included.len())
      {
        Err(DkgError::InvalidSigningSet)?;
      }
      included.sort();

      let mut secret_share = Zeroizing::new(
        self.core.interpolation.interpolation_factor::<C::F>(self.params().i(), &included) *
          self.secret_share().deref(),
      );

      let mut verification_shares = self.verification_shares();
      for (i, share) in &mut verification_shares {
        *share *= self.core.interpolation.interpolation_factor::<C::F>(*i, &included);
      }

      // The offset is included by adding it to the participant with the lowest ID
      let offset = self.offset.unwrap_or(C::F::ZERO);
      if included[0] == self.params().i() {
        *secret_share += offset;
      }
      *verification_shares.get_mut(&included[0]).unwrap() += C::generator() * offset;

      Ok(ThresholdView {
        interpolation: self.core.interpolation,
        offset,
        group_key: self.group_key(),
        secret_share,
        original_verification_shares: self.verification_shares(),
        verification_shares,
        included,
      })
    }
  }

  impl<C: Ciphersuite> From<ThresholdCore<C>> for ThresholdKeys<C> {
    fn from(keys: ThresholdCore<C>) -> ThresholdKeys<C> {
      ThresholdKeys::new(keys)
    }
  }

  impl<C: Ciphersuite> ThresholdView<C> {
    /// Return the offset for this view.
    pub fn offset(&self) -> C::F {
      self.offset
    }

    /// Return the group key.
    pub fn group_key(&self) -> C::G {
      self.group_key
    }

    /// Return the included signers.
    pub fn included(&self) -> &[Participant] {
      &self.included
    }

    /// Return the interpolation factor for a signer.
    pub fn interpolation_factor(&self, participant: Participant) -> Option<C::F> {
      if !self.included.contains(&participant) {
        None?
      }
      Some(self.interpolation.interpolation_factor(participant, &self.included))
    }

    /// Return the interpolated, offset secret share.
    pub fn secret_share(&self) -> &Zeroizing<C::F> {
      &self.secret_share
    }

    /// Return the original verification share for the specified participant.
    pub fn original_verification_share(&self, l: Participant) -> C::G {
      self.original_verification_shares[&l]
    }

    /// Return the interpolated, offset verification share for the specified participant.
    pub fn verification_share(&self, l: Participant) -> C::G {
      self.verification_shares[&l]
    }
  }
}
#[cfg(feature = "std")]
pub use lib::*;
