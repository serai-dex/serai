#![cfg_attr(not(feature = "std"), no_std)]

use core::time::Duration;

#[cfg(feature = "std")]
use zeroize::Zeroize;

use dalek_ff_group::Ristretto;
use ciphersuite::{group::GroupEncoding, Ciphersuite};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec, sr25519::Public};
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

use serai_primitives::{ExternalNetworkId, NetworkId};

mod slash_points;
pub use slash_points::*;

/// The expected duration for a session.
// 1 week
pub const SESSION_LENGTH: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The maximum length for a key.
// Support keys up to 96 bytes (BLS12-381 G2).
pub const MAX_KEY_LEN: u32 = 96;

/// The maximum amount of key shares per set.
pub const MAX_KEY_SHARES_PER_SET: u16 = 150;
pub const MAX_KEY_SHARES_PER_SET_U32: u32 = MAX_KEY_SHARES_PER_SET as u32;

/// The type used to identify a specific session of validators.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Session(pub u32);

/// The type used to identify a specific validator set during a specific session.
#[derive(
  Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidatorSet {
  pub session: Session,
  pub network: NetworkId,
}

/// The type used to identify a specific validator set during a specific session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExternalValidatorSet {
  pub session: Session,
  pub network: ExternalNetworkId,
}

impl From<ExternalValidatorSet> for ValidatorSet {
  fn from(set: ExternalValidatorSet) -> Self {
    ValidatorSet { session: set.session, network: set.network.into() }
  }
}

impl TryFrom<ValidatorSet> for ExternalValidatorSet {
  type Error = ();

  fn try_from(set: ValidatorSet) -> Result<Self, Self::Error> {
    match set.network {
      NetworkId::Serai => Err(())?,
      NetworkId::External(network) => Ok(ExternalValidatorSet { session: set.session, network }),
    }
  }
}

/// The type representing a Key from an external network.
pub type ExternalKey = BoundedVec<u8, ConstU32<MAX_KEY_LEN>>;

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for publishing data onto Serai, and their key on the external
/// network.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyPair(
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "serai_primitives::borsh_serialize_public",
      deserialize_with = "serai_primitives::borsh_deserialize_public"
    )
  )]
  pub Public,
  #[cfg_attr(
    feature = "borsh",
    borsh(
      serialize_with = "serai_primitives::borsh_serialize_bounded_vec",
      deserialize_with = "serai_primitives::borsh_deserialize_bounded_vec"
    )
  )]
  pub ExternalKey,
);
#[cfg(feature = "std")]
impl Zeroize for KeyPair {
  fn zeroize(&mut self) {
    self.0 .0.zeroize();
    self.1.as_mut().zeroize();
  }
}

/// The MuSig context for a validator set.
pub fn musig_context(set: ValidatorSet) -> [u8; 32] {
  let mut context = [0; 32];
  const DST: &[u8] = b"ValidatorSets-musig_key";
  context[.. DST.len()].copy_from_slice(DST);
  let set = set.encode();
  context[DST.len() .. (DST.len() + set.len())].copy_from_slice(&set);
  context
}

/// The MuSig public key for a validator set.
///
/// This function panics on invalid input, per the definition of `dkg::musig::musig_key`.
pub fn musig_key(set: ValidatorSet, set_keys: &[Public]) -> Public {
  let mut keys = Vec::new();
  for key in set_keys {
    keys.push(
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut key.0.as_ref())
        .expect("invalid participant"),
    );
  }
  Public(dkg_musig::musig_key_vartime::<Ristretto>(musig_context(set), &keys).unwrap().to_bytes())
}

/// The message for the `set_keys` signature.
pub fn set_keys_message(set: &ExternalValidatorSet, key_pair: &KeyPair) -> Vec<u8> {
  (b"ValidatorSets-set_keys", set, key_pair).encode()
}

/// For a set of validators whose key shares may exceed the maximum, reduce until they equal the
/// maximum.
///
/// Reduction occurs by reducing each validator in a reverse round-robin.
pub fn amortize_excess_key_shares(validators: &mut [(Public, u64)]) {
  let total_key_shares = validators.iter().map(|(_, shares)| shares).sum::<u64>();
  for i in 0 .. usize::try_from(total_key_shares.saturating_sub(u64::from(MAX_KEY_SHARES_PER_SET)))
    .unwrap()
  {
    validators[validators.len() - ((i % validators.len()) + 1)].1 -= 1;
  }
}

/// Returns the post-amortization key shares for the top validator.
///
/// Panics when `validators == 0`.
pub fn post_amortization_key_shares_for_top_validator(
  validators: usize,
  top: u64,
  key_shares: u64,
) -> u64 {
  top -
    (key_shares.saturating_sub(MAX_KEY_SHARES_PER_SET.into()) /
      u64::try_from(validators).unwrap())
}
