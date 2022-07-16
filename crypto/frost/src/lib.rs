use core::fmt::Debug;
use std::{io::Read, collections::HashMap};

use thiserror::Error;

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

mod schnorr;

pub mod curve;
use curve::Curve;
pub mod key_gen;
pub mod algorithm;
pub mod sign;

pub mod tests;

/// Parameters for a multisig
// These fields can not be made public as they should be static
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrostParams {
  /// Participants needed to sign on behalf of the group
  t: u16,
  /// Amount of participants
  n: u16,
  /// Index of the participant being acted for
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

// View of keys passable to algorithm implementations
#[derive(Clone)]
pub struct FrostView<C: Curve> {
  group_key: C::G,
  included: Vec<u16>,
  secret_share: C::F,
  verification_shares: HashMap<u16, C::G>,
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

/// Calculate the lagrange coefficient for a signing set
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrostKeys<C: Curve> {
  /// FROST Parameters
  params: FrostParams,

  /// Secret share key
  secret_share: C::F,
  /// Group key
  group_key: C::G,
  /// Verification shares
  verification_shares: HashMap<u16, C::G>,

  /// Offset applied to these keys
  offset: Option<C::F>,
}

impl<C: Curve> FrostKeys<C> {
  /// Offset the keys by a given scalar to allow for account and privacy schemes
  /// This offset is ephemeral and will not be included when these keys are serialized
  /// Keys offset multiple times will form a new offset of their sum
  /// Not IETF compliant
  pub fn offset(&self, offset: C::F) -> FrostKeys<C> {
    let mut res = self.clone();
    // Carry any existing offset
    // Enables schemes like Monero's subaddresses which have a per-subaddress offset and then a
    // one-time-key offset
    res.offset = Some(offset + res.offset.unwrap_or(C::F::zero()));
    res.group_key += C::GENERATOR * offset;
    res
  }

  pub fn params(&self) -> FrostParams {
    self.params
  }

  fn secret_share(&self) -> C::F {
    self.secret_share
  }

  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  fn verification_shares(&self) -> HashMap<u16, C::G> {
    self.verification_shares.clone()
  }

  pub fn view(&self, included: &[u16]) -> Result<FrostView<C>, FrostError> {
    if (included.len() < self.params.t.into()) || (usize::from(self.params.n) < included.len()) {
      Err(FrostError::InvalidSigningSet("invalid amount of participants included"))?;
    }

    let secret_share = self.secret_share * lagrange::<C::F>(self.params.i, &included);
    let offset = self.offset.unwrap_or(C::F::zero());
    let offset_share = offset * C::F::from(included.len().try_into().unwrap()).invert().unwrap();

    Ok(FrostView {
      group_key: self.group_key,
      secret_share: secret_share + offset_share,
      verification_shares: self
        .verification_shares
        .iter()
        .map(|(l, share)| {
          (*l, (*share * lagrange::<C::F>(*l, &included)) + (C::GENERATOR * offset_share))
        })
        .collect(),
      included: included.to_vec(),
    })
  }

  pub fn serialized_len(n: u16) -> usize {
    8 + C::ID.len() + (3 * 2) + C::F_len() + C::G_len() + (usize::from(n) * C::G_len())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(FrostKeys::<C>::serialized_len(self.params.n));
    serialized.extend(u32::try_from(C::ID.len()).unwrap().to_be_bytes());
    serialized.extend(C::ID);
    serialized.extend(&self.params.t.to_be_bytes());
    serialized.extend(&self.params.n.to_be_bytes());
    serialized.extend(&self.params.i.to_be_bytes());
    serialized.extend(self.secret_share.to_repr().as_ref());
    serialized.extend(self.group_key.to_bytes().as_ref());
    for l in 1..=self.params.n.into() {
      serialized.extend(self.verification_shares[&l].to_bytes().as_ref());
    }
    serialized
  }

  pub fn deserialize<R: Read>(cursor: &mut R) -> Result<FrostKeys<C>, FrostError> {
    {
      let missing = FrostError::InternalError("FrostKeys serialization is missing its curve");
      let different = FrostError::InternalError("deserializing FrostKeys for another curve");

      let mut id_len = [0; 4];
      cursor.read_exact(&mut id_len).map_err(|_| missing)?;
      if u32::try_from(C::ID.len()).unwrap().to_be_bytes() != id_len {
        Err(different)?;
      }

      let mut id = vec![0; C::ID.len()];
      cursor.read_exact(&mut id).map_err(|_| missing)?;
      if &id != &C::ID {
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
    let group_key =
      C::read_G(cursor).map_err(|_| FrostError::InternalError("invalid group key"))?;

    let mut verification_shares = HashMap::new();
    for l in 1..=n {
      verification_shares.insert(
        l,
        C::read_G(cursor).map_err(|_| FrostError::InternalError("invalid verification share"))?,
      );
    }

    Ok(FrostKeys {
      params: FrostParams::new(t, n, i)
        .map_err(|_| FrostError::InternalError("invalid parameters"))?,
      secret_share,
      group_key,
      verification_shares,
      offset: None,
    })
  }
}

// Validate a map of serialized values to have the expected included participants
pub(crate) fn validate_map<T>(
  map: &mut HashMap<u16, T>,
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
