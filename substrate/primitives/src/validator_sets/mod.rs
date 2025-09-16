use alloc::vec::Vec;

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::{group::GroupEncoding, GroupIo};
use dalek_ff_group::Ristretto;

use crate::{
  crypto::{Public, KeyPair},
  network_id::{ExternalNetworkId, NetworkId},
  balance::Amount,
};

mod slashes;
pub use slashes::*;

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
pub struct Session(pub u32);

/// The type used to identify a specific set of validators for an external network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
pub struct ExternalValidatorSet {
  /// The network this set of validators are for.
  pub network: ExternalNetworkId,
  /// Which session this set of validators is occuring during.
  pub session: Session,
}

/// The type used to identify a specific set of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen, scale::DecodeWithMemTracking)
)]
pub struct ValidatorSet {
  /// The network this set of validators are for.
  pub network: NetworkId,
  /// Which session this set of validators is occuring during.
  pub session: Session,
}

impl From<ExternalValidatorSet> for ValidatorSet {
  fn from(set: ExternalValidatorSet) -> Self {
    ValidatorSet { network: set.network.into(), session: set.session }
  }
}

impl TryFrom<ValidatorSet> for ExternalValidatorSet {
  type Error = ();

  fn try_from(set: ValidatorSet) -> Result<Self, Self::Error> {
    set.network.try_into().map(|network| ExternalValidatorSet { network, session: set.session })
  }
}

impl ExternalValidatorSet {
  /// The MuSig context for this validator set.
  pub fn musig_context(&self) -> [u8; 32] {
    let mut res = [0; 32];

    const DST: &[u8] = b"ValidatorSets-musig_key";
    res[0] = u8::try_from(DST.len()).unwrap();
    #[allow(clippy::range_plus_one)]
    res[1 .. (1 + DST.len())].copy_from_slice(DST);

    // Check we have room to encode into `res`, using the approximate `size_of` for the max size of
    // the serialization
    const _ASSERT_MORE_BYTES_THAN_SIZE: [();
      32 - (1 + DST.len()) - core::mem::size_of::<ExternalValidatorSet>()] = [(); _];

    let encoded = borsh::to_vec(&self).unwrap();
    res[(1 + DST.len()) .. (1 + DST.len() + encoded.len())].copy_from_slice(&encoded);

    res
  }

  /// The MuSig public key for a validator set.
  ///
  /// This function panics on invalid input, per the definition of `dkg::musig::musig_key`.
  pub fn musig_key(&self, set_keys: &[Public]) -> Public {
    let mut keys = Vec::new();
    for key in set_keys {
      keys.push(
        <Ristretto as GroupIo>::read_G::<&[u8]>(&mut key.0.as_ref()).expect("invalid participant"),
      );
    }
    Public(dkg::musig_key::<Ristretto>(self.musig_context(), &keys).unwrap().to_bytes())
  }

  /// The message for the `set_keys` signature.
  pub fn set_keys_message(&self, key_pair: &KeyPair) -> Vec<u8> {
    borsh::to_vec(&(b"ValidatorSets-set_keys", self, key_pair)).unwrap()
  }
}

/// The representation for an amount of key shares.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(scale::Encode, scale::Decode, scale::MaxEncodedLen)
)]
pub struct KeyShares(pub u16);

impl KeyShares {
  /// One key share.
  pub const ONE: KeyShares = KeyShares(1);
  /// The maximum amount of key shares per set.
  pub const MAX_PER_SET: u16 = 150;
  /// The maximum amount of key shares per set, represented as a `u32`.
  pub const MAX_PER_SET_U32: u32 = 150;

  /// Create key shares from a `u16`.
  ///
  /// This will saturate the value if the `u16` exceeds the maximum amount of key shares.
  pub fn saturating_from(key_shares: u16) -> KeyShares {
    KeyShares(key_shares.min(Self::MAX_PER_SET))
  }

  /// Create key shares from an allocation.
  ///
  /// Presumably panics if `allocation_per_key_share` is zero.
  pub fn from_allocation(allocation: Amount, allocation_per_key_share: Amount) -> Self {
    Self::saturating_from(
      u16::try_from(allocation.0 / allocation_per_key_share.0).unwrap_or(u16::MAX),
    )
  }

  /// For a set of validators whose key shares may exceed the maximum, reduce until they are less
  /// than or equal to the maximum.
  ///
  /// Returns the new amount of validators with a non-zero amount of key shares.
  ///
  /// This runs in time linear to the exceeded key shares and may panic if:
  ///   - The total amount of key shares exceeds `u16::MAX`.
  ///   - The list of validators is absurdly long
  ///   - The list of validators includes validators without key shares
  ///
  /// Reduction occurs by reducing each validator in a reverse round-robin. This means the
  /// validators with the least key shares are evicted first.
  #[must_use]
  pub fn amortize_excess(validators: &mut [(sp_core::sr25519::Public, KeyShares)]) -> usize {
    let total_key_shares = validators.iter().map(|(_key, shares)| shares.0).sum::<u16>();
    let mut actual_len = validators.len();
    let mut offset = 1;
    for _ in 0 .. usize::from(total_key_shares.saturating_sub(Self::MAX_PER_SET)) {
      // If the offset exceeds the new length, reset it
      if offset > actual_len {
        offset = 1;
      }

      // Take one key share from this validator
      let index = actual_len - offset;
      validators[index].1 .0 -= 1;
      // If they now have zero key shares, shrink the length and continue
      if validators[index].1 .0 == 0 {
        actual_len -= 1;
        continue;
      }

      // Increment the offset to take from the next validator on the next iteration
      offset += 1;
    }
    actual_len
  }
}

impl TryFrom<u16> for KeyShares {
  type Error = ();
  fn try_from(value: u16) -> Result<Self, ()> {
    if value > Self::MAX_PER_SET {
      Err(())
    } else {
      Ok(Self(value))
    }
  }
}
