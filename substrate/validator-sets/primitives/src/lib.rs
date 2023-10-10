#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use zeroize::Zeroize;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, sr25519::Public, bounded::BoundedVec};
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

use serai_primitives::NetworkId;

/// The maximum amount of validators per set.
pub const MAX_VALIDATORS_PER_SET: u32 = 150;
// Support keys up to 96 bytes (BLS12-381 G2).
const MAX_KEY_LEN: u32 = 96;

/// The type used to identify a specific session of validators.
#[derive(
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  Debug,
  Serialize,
  Deserialize,
  Encode,
  Decode,
  TypeInfo,
  MaxEncodedLen,
  Default,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct Session(pub u32);

/// The type used to identify a specific validator set during a specific session.
#[derive(
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  Debug,
  Serialize,
  Deserialize,
  Encode,
  Decode,
  TypeInfo,
  MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub struct ValidatorSet {
  pub session: Session,
  pub network: NetworkId,
}

type MaxKeyLen = ConstU32<MAX_KEY_LEN>;
/// The type representing a Key from an external network.
pub type ExternalKey = BoundedVec<u8, MaxKeyLen>;

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for signing Batches, and their key on the external network.
pub type KeyPair = (Public, ExternalKey);

/// The MuSig context for a validator set.
pub fn musig_context(set: ValidatorSet) -> Vec<u8> {
  [b"ValidatorSets-musig_key".as_ref(), &set.encode()].concat()
}

/// The MuSig public key for a validator set.
///
/// This function panics on invalid input.
pub fn musig_key(set: ValidatorSet, set_keys: &[Public]) -> Public {
  let mut keys = Vec::new();
  for key in set_keys {
    keys.push(
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut key.0.as_ref())
        .expect("invalid participant"),
    );
  }
  Public(dkg::musig::musig_key::<Ristretto>(&musig_context(set), &keys).unwrap().to_bytes())
}

/// The message for the set_keys signature.
pub fn set_keys_message(set: &ValidatorSet, key_pair: &KeyPair) -> Vec<u8> {
  [b"ValidatorSets-key_pair".as_ref(), &(set, key_pair).encode()].concat()
}
