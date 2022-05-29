use core::{ops::Mul, fmt::Debug};
use std::collections::HashMap;

use thiserror::Error;

use ff::{Field, PrimeField};
use group::{Group, GroupOps};

mod schnorr;

pub mod key_gen;
pub mod algorithm;
pub mod sign;

pub mod tests;

/// Set of errors for curve-related operations, namely encoding and decoding
#[derive(Clone, Error, Debug)]
pub enum CurveError {
  #[error("invalid length for data (expected {0}, got {0})")]
  InvalidLength(usize, usize),
  #[error("invalid scalar")]
  InvalidScalar,
  #[error("invalid point")]
  InvalidPoint,
}

/// Unified trait to manage a field/group
// This should be moved into its own crate if the need for generic cryptography over ff/group
// continues, which is the exact reason ff/group exists (to provide a generic interface)
// elliptic-curve exists, yet it doesn't really serve the same role, nor does it use &[u8]/Vec<u8>
// It uses GenericArray which will hopefully be deprecated as Rust evolves and doesn't offer enough
// advantages in the modern day to be worth the hassle -- Kayaba
pub trait Curve: Clone + Copy + PartialEq + Eq + Debug {
  /// Field element type
  // This is available via G::Scalar yet `C::G::Scalar` is ambiguous, forcing horrific accesses
  type F: PrimeField;
  /// Group element type
  type G: Group<Scalar = Self::F> + GroupOps;
  /// Precomputed table type
  type T: Mul<Self::F, Output = Self::G>;

  /// ID for this curve
  fn id() -> String;
  /// Byte length of the curve ID
  // While curve.id().len() is trivial, this bounds it to u8 and lets us ignore the possibility it
  // contains Unicode, therefore having a String length which is different from its byte length
  fn id_len() -> u8;

  /// Generator for the group
  // While group does provide this in its API, Jubjub users will want to use a custom basepoint
  fn generator() -> Self::G;

  /// Table for the generator for the group
  /// If there isn't a precomputed table available, the generator itself should be used
  fn generator_table() -> Self::T;

  /// If little endian is used for the scalar field's Repr
  fn little_endian() -> bool;

  /// Hash the message for the binding factor. H3 from the IETF draft
  // This doesn't actually need to be part of Curve as it does nothing with the curve
  // This also solely relates to FROST and with a proper Algorithm/HRAM, all projects using
  // aggregatable signatures over this curve will work without issue
  // It is kept here as Curve + H{1, 2, 3} is effectively a ciphersuite according to the IETF draft
  // and moving it to Schnorr would force all of them into being ciphersuite-specific
  // H2 is left to the Schnorr Algorithm as H2 is the H used in HRAM, which Schnorr further
  // modularizes
  fn hash_msg(msg: &[u8]) -> Vec<u8>;

  /// Hash the commitments and message to calculate the binding factor. H1 from the IETF draft
  fn hash_binding_factor(binding: &[u8]) -> Self::F;

  // The following methods would optimally be F:: and G:: yet developers can't control F/G
  // They can control a trait they pass into this library

  /// Field element from hash. Used during key gen and by other crates under Serai as a general
  /// utility
  // Not parameterized by Digest as it's fine for it to use its own hash function as relevant to
  // hash_msg and hash_binding_factor
  #[allow(non_snake_case)]
  fn hash_to_F(data: &[u8]) -> Self::F;

  /// Constant size of a serialized field element
  // The alternative way to grab this would be either serializing a junk element and getting its
  // length or doing a naive division of its BITS property by 8 and assuming a lack of padding
  #[allow(non_snake_case)]
  fn F_len() -> usize;

  /// Constant size of a serialized group element
  // We could grab the serialization as described above yet a naive developer may use a
  // non-constant size encoding, proving yet another reason to force this to be a provided constant
  // A naive developer could still provide a constant for a variable length encoding, yet at least
  // that is on them
  #[allow(non_snake_case)]
  fn G_len() -> usize;

  /// Field element from slice. Preferred to be canonical yet does not have to be
  // Required due to the lack of standardized encoding functions provided by ff/group
  // While they do technically exist, their usage of Self::Repr breaks all potential library usage
  // without helper functions like this
  #[allow(non_snake_case)]
  fn F_from_slice(slice: &[u8]) -> Result<Self::F, CurveError>;

  /// Group element from slice. Must require canonicity or risks differing binding factors
  #[allow(non_snake_case)]
  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError>;

  /// Obtain a vector of the byte encoding of F
  #[allow(non_snake_case)]
  fn F_to_bytes(f: &Self::F) -> Vec<u8>;

  /// Obtain a vector of the byte encoding of G
  #[allow(non_snake_case)]
  fn G_to_bytes(g: &Self::G) -> Vec<u8>;
}

/// Parameters for a multisig
// These fields can not be made public as they should be static
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MultisigParams {
  /// Participants needed to sign on behalf of the group
  t: u16,
  /// Amount of participants
  n: u16,
  /// Index of the participant being acted for
  i: u16,
}

impl MultisigParams {
  pub fn new(
    t: u16,
    n: u16,
    i: u16
  ) -> Result<MultisigParams, FrostError> {
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

    Ok(MultisigParams{ t, n, i })
  }

  pub fn t(&self) -> u16 { self.t }
  pub fn n(&self) -> u16 { self.n }
  pub fn i(&self) -> u16 { self.i }
}

#[derive(Clone, Error, Debug)]
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
  InvalidSigningSet(String),
  #[error("invalid participant quantity (expected {0}, got {1})")]
  InvalidParticipantQuantity(usize, usize),
  #[error("duplicated participant index ({0})")]
  DuplicatedIndex(usize),
  #[error("missing participant {0}")]
  MissingParticipant(u16),
  #[error("invalid commitment (participant {0})")]
  InvalidCommitment(u16),
  #[error("invalid proof of knowledge (participant {0})")]
  InvalidProofOfKnowledge(u16),
  #[error("invalid share (participant {0})")]
  InvalidShare(u16),
  #[error("invalid key generation state machine transition (expected {0}, was {1})")]
  InvalidKeyGenTransition(key_gen::State, key_gen::State),

  #[error("invalid sign state machine transition (expected {0}, was {1})")]
  InvalidSignTransition(sign::State, sign::State),

  #[error("internal error ({0})")]
  InternalError(String),
}

// View of keys passable to algorithm implementations
#[derive(Clone)]
pub struct MultisigView<C: Curve> {
  group_key: C::G,
  included: Vec<u16>,
  secret_share: C::F,
  verification_shares: HashMap<u16, C::G>,
}

impl<C: Curve> MultisigView<C> {
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
pub fn lagrange<F: PrimeField>(
  i: u16,
  included: &[u16],
) -> F {
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
pub struct MultisigKeys<C: Curve> {
  /// Multisig Parameters
  params: MultisigParams,

  /// Secret share key
  secret_share: C::F,
  /// Group key
  group_key: C::G,
  /// Verification shares
  verification_shares: HashMap<u16, C::G>,

  /// Offset applied to these keys
  offset: Option<C::F>,
}

impl<C: Curve> MultisigKeys<C> {
  pub fn offset(&self, offset: C::F) -> MultisigKeys<C> {
    let mut res = self.clone();
    // Carry any existing offset
    // Enables schemes like Monero's subaddresses which have a per-subaddress offset and then a
    // one-time-key offset
    res.offset = Some(offset + res.offset.unwrap_or(C::F::zero()));
    res
  }

  pub fn params(&self) -> MultisigParams {
    self.params
  }

  pub fn secret_share(&self) -> C::F {
    self.secret_share
  }

  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub fn verification_shares(&self) -> HashMap<u16, C::G> {
    self.verification_shares.clone()
  }

  pub fn view(&self, included: &[u16]) -> Result<MultisigView<C>, FrostError> {
    if (included.len() < self.params.t.into()) || (usize::from(self.params.n) < included.len()) {
      Err(FrostError::InvalidSigningSet("invalid amount of participants included".to_string()))?;
    }

    let secret_share = self.secret_share * lagrange::<C::F>(self.params.i, &included);
    let offset = self.offset.unwrap_or(C::F::zero());
    let offset_share = offset * C::F::from(included.len().try_into().unwrap()).invert().unwrap();

    Ok(MultisigView {
      group_key: self.group_key + (C::generator_table() * offset),
      secret_share: secret_share + offset_share,
      verification_shares: self.verification_shares.iter().map(
        |(l, share)| (
          *l,
          (*share * lagrange::<C::F>(*l, &included)) + (C::generator_table() * offset_share)
        )
      ).collect(),
      included: included.to_vec(),
    })
  }

  pub fn serialized_len(n: u16) -> usize {
    1 + usize::from(C::id_len()) + (3 * 2) + C::F_len() + C::G_len() + (usize::from(n) * C::G_len())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(
      1 + usize::from(C::id_len()) + MultisigKeys::<C>::serialized_len(self.params.n)
    );
    serialized.push(C::id_len());
    serialized.extend(C::id().as_bytes());
    serialized.extend(&self.params.n.to_le_bytes());
    serialized.extend(&self.params.t.to_le_bytes());
    serialized.extend(&self.params.i.to_le_bytes());
    serialized.extend(&C::F_to_bytes(&self.secret_share));
    serialized.extend(&C::G_to_bytes(&self.group_key));
    for l in 1 ..= self.params.n.into() {
      serialized.extend(&C::G_to_bytes(&self.verification_shares[&l]));
    }

    serialized
  }

  pub fn deserialize(serialized: &[u8]) -> Result<MultisigKeys<C>, FrostError> {
    if serialized.len() < 1 {
      Err(FrostError::InternalError("MultisigKeys serialization is empty".to_string()))?;
    }

    let id_len: usize = serialized[0].into();
    let mut cursor = 1;

    if serialized.len() < (cursor + id_len) {
      Err(FrostError::InternalError("ID wasn't included".to_string()))?;
    }

    let id = &serialized[cursor .. (cursor + id_len)];
    if C::id().as_bytes() != id {
      Err(
        FrostError::InternalError(
          "curve is distinct between serialization and deserialization".to_string()
        )
      )?;
    }
    cursor += id_len;

    if serialized.len() < (cursor + 8) {
      Err(FrostError::InternalError("participant quantity wasn't included".to_string()))?;
    }

    let n = u16::from_le_bytes(serialized[cursor .. (cursor + 2)].try_into().unwrap());
    cursor += 2;
    if serialized.len() != MultisigKeys::<C>::serialized_len(n) {
      Err(FrostError::InternalError("incorrect serialization length".to_string()))?;
    }

    let t = u16::from_le_bytes(serialized[cursor .. (cursor + 2)].try_into().unwrap());
    cursor += 2;
    let i = u16::from_le_bytes(serialized[cursor .. (cursor + 2)].try_into().unwrap());
    cursor += 2;

    let secret_share = C::F_from_slice(&serialized[cursor .. (cursor + C::F_len())])
      .map_err(|_| FrostError::InternalError("invalid secret share".to_string()))?;
    cursor += C::F_len();
    let group_key = C::G_from_slice(&serialized[cursor .. (cursor + C::G_len())])
      .map_err(|_| FrostError::InternalError("invalid group key".to_string()))?;
    cursor += C::G_len();

    let mut verification_shares = HashMap::new();
    for l in 1 ..= n {
      verification_shares.insert(
        l,
        C::G_from_slice(&serialized[cursor .. (cursor + C::G_len())])
          .map_err(|_| FrostError::InternalError("invalid verification share".to_string()))?
      );
      cursor += C::G_len();
    }

    Ok(
      MultisigKeys {
        params: MultisigParams::new(t, n, i)
          .map_err(|_| FrostError::InternalError("invalid parameters".to_string()))?,
        secret_share,
        group_key,
        verification_shares,
        offset: None
      }
    )
  }
}

// Validate a map of serialized values to have the expected included participants
pub(crate) fn validate_map<T>(
  map: &mut HashMap<u16, T>,
  included: &[u16],
  ours: (u16, T)
) -> Result<(), FrostError> {
  map.insert(ours.0, ours.1);

  if map.len() != included.len() {
    Err(FrostError::InvalidParticipantQuantity(included.len(), map.len()))?;
  }

  for included in included {
    if !map.contains_key(included) {
      Err(FrostError::MissingParticipant(*included))?;
    }
  }

  Ok(())
}
