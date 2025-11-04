#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{
  ops::Deref,
  fmt::{self, Debug},
};
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::{sync::Arc, vec, vec::Vec, collections::HashMap, io};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  GroupIo, Id,
};

/// The ID of a participant, defined as a non-zero u16.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Zeroize)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
pub struct Participant(u16);
impl Participant {
  /// Create a new Participant identifier from a u16.
  pub const fn new(i: u16) -> Option<Participant> {
    if i == 0 {
      None
    } else {
      Some(Participant(i))
    }
  }

  /// Convert a Participant identifier to bytes.
  #[allow(clippy::wrong_self_convention)]
  pub const fn to_bytes(&self) -> [u8; 2] {
    self.0.to_le_bytes()
  }

  /// Create an iterator over participant indexes.
  pub fn iter() -> impl Iterator<Item = Participant> {
    struct ParticipantIterator(u16);
    impl Iterator for ParticipantIterator {
      type Item = Participant;
      fn next(&mut self) -> Option<Self::Item> {
        self.0 = self.0.checked_add(1)?;
        Some(Participant(self.0))
      }
    }
    ParticipantIterator(0)
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

/// Errors encountered when working with threshold keys.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum DkgError {
  /// A parameter was zero.
  #[error("a parameter was 0 (threshold {t}, participants {n})")]
  ZeroParameter {
    /// The specified threshold.
    t: u16,
    /// The specified total amount of participants.
    n: u16,
  },

  /// The threshold exceeded the amount of participants.
  #[error("invalid threshold (max {n}, got {t})")]
  InvalidThreshold {
    /// The specified threshold.
    t: u16,
    /// The specified total amount of participants.
    n: u16,
  },

  /// Invalid participant identifier.
  #[error("invalid participant (1 <= participant <= {n}, yet participant is {participant})")]
  InvalidParticipant {
    /// The total amount of participants.
    n: u16,
    /// The specified participant.
    participant: Participant,
  },

  /// An incorrect amount of participants was specified.
  #[error("incorrect amount of verification shares (n = {n} yet {shares} provided)")]
  IncorrectAmountOfVerificationShares {
    /// The amount of participants.
    n: u16,
    /// The amount of shares provided.
    shares: usize,
  },

  /// An inapplicable method of interpolation was specified.
  #[error("inapplicable method of interpolation ({0})")]
  InapplicableInterpolation(&'static str),

  /// An incorrect amount of participants was specified.
  #[error("incorrect amount of participants. {t} <= amount <= {n}, yet amount is {amount}")]
  IncorrectAmountOfParticipants {
    /// The threshold required.
    t: u16,
    /// The total amount of participants.
    n: u16,
    /// The amount of participants specified.
    amount: usize,
  },

  /// A participant was duplicated.
  #[error("a participant ({0}) was duplicated")]
  DuplicatedParticipant(Participant),

  /// Not participating in declared signing set.
  #[error("not participating in declared signing set")]
  NotParticipating,
}

// Manually implements BorshDeserialize so we can enforce it's a valid index
#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for Participant {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Participant::new(u16::deserialize_reader(reader)?)
      .ok_or_else(|| io::Error::other("invalid participant"))
  }
}

/// Parameters for a multisig.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize))]
pub struct ThresholdParams {
  /// Participants needed to sign on behalf of the group.
  t: u16,
  /// Amount of participants.
  n: u16,
  /// Index of the participant being acted for.
  i: Participant,
}

/// An iterator over all participant indexes.
struct AllParticipantIndexes {
  i: u16,
  n: u16,
}
impl Iterator for AllParticipantIndexes {
  type Item = Participant;
  fn next(&mut self) -> Option<Participant> {
    if self.i > self.n {
      None?;
    }
    let res = Participant::new(self.i).unwrap();

    // If i == n == u16::MAX, we cause `i > n` by setting `n` to `0` so the iterator becomes empty
    if self.i == u16::MAX {
      self.n = 0;
    } else {
      self.i += 1;
    }

    Some(res)
  }
}

impl ThresholdParams {
  /// Create a new set of parameters.
  pub const fn new(t: u16, n: u16, i: Participant) -> Result<ThresholdParams, DkgError> {
    if (t == 0) || (n == 0) {
      return Err(DkgError::ZeroParameter { t, n });
    }

    if t > n {
      return Err(DkgError::InvalidThreshold { t, n });
    }
    if i.0 > n {
      return Err(DkgError::InvalidParticipant { n, participant: i });
    }

    Ok(ThresholdParams { t, n, i })
  }

  /// The threshold for a multisig with these parameters.
  pub const fn t(&self) -> u16 {
    self.t
  }
  /// The amount of participants for a multisig with these parameters.
  pub const fn n(&self) -> u16 {
    self.n
  }
  /// The participant index of the share with these parameters.
  pub const fn i(&self) -> Participant {
    self.i
  }

  /// An iterator over all participant indexes.
  pub fn all_participant_indexes(&self) -> impl Iterator<Item = Participant> {
    AllParticipantIndexes { i: 1, n: self.n }
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

/// A method of interpolation.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum Interpolation<F: Zeroize + PrimeField> {
  /// A list of constant coefficients, one for each of the secret key shares.
  /*
    There's no benefit to using a full linear combination here, as the additive term would have
    an entirely known evaluation with a fixed, public coefficient of `1`. Accordingly, the entire
    key can simply be offset with the additive term to achieve the same effect.
  */
  Constant(Vec<F>),
  /// Lagrange interpolation.
  Lagrange,
}

impl<F: Zeroize + PrimeField> Interpolation<F> {
  /// The interpolation factor for this participant, within this signing set.
  fn interpolation_factor(&self, i: Participant, included: &[Participant]) -> F {
    match self {
      Interpolation::Constant(c) => c[usize::from(u16::from(i) - 1)],
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

/// A key share for a thresholdized secret key.
///
/// This is the 'core' structure containing all relevant data, expected to be wrapped into an
/// heap-allocated pointer to minimize copies on the stack (`ThresholdKeys`, the publicly exposed
/// type).
#[derive(Clone, PartialEq, Eq)]
struct ThresholdCore<C: GroupIo + Id> {
  params: ThresholdParams,
  group_key: C::G,
  verification_shares: HashMap<Participant, C::G>,
  interpolation: Interpolation<C::F>,
  secret_share: Zeroizing<C::F>,
}

impl<C: GroupIo + Id> fmt::Debug for ThresholdCore<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ThresholdCore")
      .field("params", &self.params)
      .field("group_key", &self.group_key)
      .field("verification_shares", &self.verification_shares)
      .field("interpolation", &self.interpolation)
      .finish_non_exhaustive()
  }
}

impl<C: GroupIo + Id> Zeroize for ThresholdCore<C> {
  fn zeroize(&mut self) {
    self.params.zeroize();
    self.group_key.zeroize();
    for share in self.verification_shares.values_mut() {
      share.zeroize();
    }
    self.interpolation.zeroize();
    self.secret_share.zeroize();
  }
}

/// Threshold keys usable for signing.
#[derive(Clone, Debug, Zeroize)]
pub struct ThresholdKeys<C: GroupIo + Id> {
  // Core keys.
  #[zeroize(skip)]
  core: Arc<Zeroizing<ThresholdCore<C>>>,

  // Scalar applied to these keys.
  scalar: C::F,
  // Offset applied to these keys.
  offset: C::F,
}

/// View of keys, interpolated and with the expected linear combination taken for usage.
#[derive(Clone)]
pub struct ThresholdView<C: GroupIo + Id> {
  interpolation: Interpolation<C::F>,
  scalar: C::F,
  offset: C::F,
  group_key: C::G,
  included: Vec<Participant>,
  secret_share: Zeroizing<C::F>,
  original_verification_shares: HashMap<Participant, C::G>,
  verification_shares: HashMap<Participant, C::G>,
}

impl<C: GroupIo + Id> fmt::Debug for ThresholdView<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("ThresholdView")
      .field("interpolation", &self.interpolation)
      .field("scalar", &self.scalar)
      .field("offset", &self.offset)
      .field("group_key", &self.group_key)
      .field("included", &self.included)
      .field("original_verification_shares", &self.original_verification_shares)
      .field("verification_shares", &self.verification_shares)
      .finish_non_exhaustive()
  }
}

impl<C: GroupIo + Id> Zeroize for ThresholdView<C> {
  fn zeroize(&mut self) {
    self.scalar.zeroize();
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

impl<C: GroupIo + Id> ThresholdKeys<C> {
  /// Create a new set of ThresholdKeys.
  pub fn new(
    params: ThresholdParams,
    interpolation: Interpolation<C::F>,
    secret_share: Zeroizing<C::F>,
    verification_shares: HashMap<Participant, C::G>,
  ) -> Result<ThresholdKeys<C>, DkgError> {
    if verification_shares.len() != usize::from(params.n()) {
      Err(DkgError::IncorrectAmountOfVerificationShares {
        n: params.n(),
        shares: verification_shares.len(),
      })?;
    }
    for participant in verification_shares.keys().copied() {
      if u16::from(participant) > params.n() {
        Err(DkgError::InvalidParticipant { n: params.n(), participant })?;
      }
    }

    match &interpolation {
      Interpolation::Constant(_) => {
        if params.t() != params.n() {
          Err(DkgError::InapplicableInterpolation("constant interpolation for keys where t != n"))?;
        }
      }
      Interpolation::Lagrange => {}
    }

    let t = (1 ..= params.t()).map(Participant).collect::<Vec<_>>();
    let group_key =
      t.iter().map(|i| verification_shares[i] * interpolation.interpolation_factor(*i, &t)).sum();

    Ok(ThresholdKeys {
      core: Arc::new(Zeroizing::new(ThresholdCore {
        params,
        interpolation,
        secret_share,
        group_key,
        verification_shares,
      })),
      scalar: C::F::ONE,
      offset: C::F::ZERO,
    })
  }

  /// Scale the keys by a given scalar to allow for various account and privacy schemes.
  ///
  /// This scalar is ephemeral and will not be included when these keys are serialized. The
  /// scalar is applied on top of any already-existing scalar/offset.
  ///
  /// Returns `None` if the scalar is equal to `0`.
  #[must_use]
  pub fn scale(mut self, scalar: C::F) -> Option<ThresholdKeys<C>> {
    if bool::from(scalar.is_zero()) {
      None?;
    }
    self.scalar *= scalar;
    self.offset *= scalar;
    Some(self)
  }

  /// Offset the keys by a given scalar to allow for various account and privacy schemes.
  ///
  /// This offset is ephemeral and will not be included when these keys are serialized. The
  /// offset is applied on top of any already-existing scalar/offset.
  #[must_use]
  pub fn offset(mut self, offset: C::F) -> ThresholdKeys<C> {
    self.offset += offset;
    self
  }

  /// Return the current scalar in-use for these keys.
  pub fn current_scalar(&self) -> C::F {
    self.scalar
  }

  /// Return the current offset in-use for these keys.
  pub fn current_offset(&self) -> C::F {
    self.offset
  }

  /// Return the parameters for these keys.
  pub fn params(&self) -> ThresholdParams {
    self.core.params
  }

  /// Return the original group key, without any tweaks applied.
  pub fn original_group_key(&self) -> C::G {
    self.core.group_key
  }

  /// Return the interpolation method for these keys.
  pub fn interpolation(&self) -> &Interpolation<C::F> {
    &self.core.interpolation
  }

  /// Return the group key, with the expected linear combination taken.
  pub fn group_key(&self) -> C::G {
    (self.core.group_key * self.scalar) + (C::generator() * self.offset)
  }

  /// Return the underlying secret share for these keys, without any tweaks applied.
  pub fn original_secret_share(&self) -> &Zeroizing<C::F> {
    &self.core.secret_share
  }

  /// Return the original (untweaked) verification share for the specified participant.
  ///
  /// This will panic if the participant index is invalid for these keys.
  pub fn original_verification_share(&self, l: Participant) -> C::G {
    self.core.verification_shares[&l]
  }

  /// Obtain a view of these keys, interpolated for the specified signing set, with the specified
  /// linear combination taken.
  pub fn view(&self, mut included: Vec<Participant>) -> Result<ThresholdView<C>, DkgError> {
    if (included.len() < self.params().t.into()) ||
      (usize::from(self.params().n()) < included.len())
    {
      Err(DkgError::IncorrectAmountOfParticipants {
        t: self.params().t,
        n: self.params().n,
        amount: included.len(),
      })?;
    }
    included.sort();
    {
      let mut found = included[0] == self.params().i();
      for i in 1 .. included.len() {
        if included[i - 1] == included[i] {
          Err(DkgError::DuplicatedParticipant(included[i]))?;
        }
        found |= included[i] == self.params().i();
      }
      if !found {
        Err(DkgError::NotParticipating)?;
      }
    }
    {
      let last = *included.last().unwrap();
      if u16::from(last) > self.params().n() {
        Err(DkgError::InvalidParticipant { n: self.params().n(), participant: last })?;
      }
    }

    // The interpolation occurs multiplicatively, letting us scale by the scalar now
    let secret_share_scaled = Zeroizing::new(self.scalar * self.original_secret_share().deref());
    let mut secret_share = Zeroizing::new(
      self.core.interpolation.interpolation_factor(self.params().i(), &included) *
        secret_share_scaled.deref(),
    );

    let mut verification_shares = HashMap::with_capacity(included.len());
    for i in &included {
      let verification_share = self.core.verification_shares[i];
      let verification_share = verification_share *
        self.scalar *
        self.core.interpolation.interpolation_factor(*i, &included);
      verification_shares.insert(*i, verification_share);
    }

    /*
      The offset is included by adding it to the participant with the lowest ID.

      This is done after interpolating to ensure, regardless of the method of interpolation, that
      the method of interpolation does not scale the offset. For Lagrange interpolation, we could
      add the offset to every key share before interpolating, yet for Constant interpolation, we
      _have_ to add it as we do here (which also works even when we intend to perform Lagrange
      interpolation).
    */
    if included[0] == self.params().i() {
      *secret_share += self.offset;
    }
    *verification_shares.get_mut(&included[0]).unwrap() += C::generator() * self.offset;

    Ok(ThresholdView {
      interpolation: self.core.interpolation.clone(),
      scalar: self.scalar,
      offset: self.offset,
      group_key: self.group_key(),
      secret_share,
      original_verification_shares: self.core.verification_shares.clone(),
      verification_shares,
      included,
    })
  }

  /// Write these keys to a type satisfying `std::io::Write`.
  ///
  /// This will not include the ephemeral scalar/offset.
  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(C::ID.len()).unwrap().to_le_bytes())?;
    writer.write_all(C::ID)?;
    writer.write_all(&self.core.params.t.to_le_bytes())?;
    writer.write_all(&self.core.params.n.to_le_bytes())?;
    writer.write_all(&self.core.params.i.to_bytes())?;
    match &self.core.interpolation {
      Interpolation::Constant(c) => {
        writer.write_all(&[0])?;
        for c in c {
          writer.write_all(c.to_repr().as_ref())?;
        }
      }
      Interpolation::Lagrange => writer.write_all(&[1])?,
    };
    let mut share_bytes = self.core.secret_share.to_repr();
    writer.write_all(share_bytes.as_ref())?;
    share_bytes.as_mut().zeroize();
    for l in 1 ..= self.core.params.n {
      writer.write_all(
        self.core.verification_shares[&Participant::new(l).unwrap()].to_bytes().as_ref(),
      )?;
    }
    Ok(())
  }

  /// Serialize these keys to a `Vec<u8>`.
  ///
  /// This will not include the ephemeral scalar/offset.
  pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
    let mut serialized = Zeroizing::new(vec![]);
    self.write::<Vec<u8>>(serialized.as_mut()).unwrap();
    serialized
  }

  /// Read keys from a type satisfying `std::io::Read`.
  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<ThresholdKeys<C>> {
    {
      let different = || io::Error::other("deserializing ThresholdKeys for another curve");

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
      0 => Interpolation::Constant({
        let mut res = Vec::with_capacity(usize::from(n));
        for _ in 0 .. n {
          res.push(C::read_F(reader)?);
        }
        res
      }),
      1 => Interpolation::Lagrange,
      _ => Err(io::Error::other("invalid interpolation method"))?,
    };

    let secret_share = Zeroizing::new(C::read_F(reader)?);

    let mut verification_shares = HashMap::new();
    for l in (1 ..= n).map(Participant) {
      verification_shares.insert(l, C::read_G(reader)?);
    }

    ThresholdKeys::new(
      ThresholdParams::new(t, n, i).map_err(io::Error::other)?,
      interpolation,
      secret_share,
      verification_shares,
    )
    .map_err(io::Error::other)
  }
}

impl<C: GroupIo + Id> ThresholdView<C> {
  /// Return the scalar applied to this view.
  pub fn scalar(&self) -> C::F {
    self.scalar
  }

  /// Return the offset applied to this view.
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

  /// Return the interpolated secret share, with the expected linear combination taken.
  pub fn secret_share(&self) -> &Zeroizing<C::F> {
    &self.secret_share
  }

  /// Return the original (untweaked) verification share for the specified participant.
  ///
  /// This will panic if the participant index is invalid for these keys.
  pub fn original_verification_share(&self, l: Participant) -> C::G {
    self.original_verification_shares[&l]
  }

  /// Return the interpolated verification share, with the expected linear combination taken,
  /// for the specified participant.
  ///
  /// This will panic if the participant was not included in the signing set.
  pub fn verification_share(&self, l: Participant) -> C::G {
    self.verification_shares[&l]
  }
}
