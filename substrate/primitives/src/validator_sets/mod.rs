use alloc::vec::Vec;

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::{group::GroupEncoding, GroupIo};
use dalek_ff_group::Ristretto;

use crate::{
  constants::MAX_KEY_SHARES_PER_SET,
  crypto::{Public, KeyPair},
  network_id::{ExternalNetworkId, NetworkId},
};

mod slashes;
pub use slashes::*;

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct Session(pub u32);

/// The type used to identify a specific set of validators for an external network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
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
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
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

/// For a set of validators whose key shares may exceed the maximum, reduce until they are less
/// than or equal to the maximum.
///
/// This runs in time linear to the exceed key shares and assumes the excess fits within a usize,
/// panicking otherwise.
///
/// Reduction occurs by reducing each validator in a reverse round-robin. This means the worst
/// validators lose their key shares first.
pub fn amortize_excess_key_shares(validators: &mut [(sp_core::sr25519::Public, u64)]) {
  let total_key_shares = validators.iter().map(|(_key, shares)| shares).sum::<u64>();
  for i in 0 .. usize::try_from(total_key_shares.saturating_sub(u64::from(MAX_KEY_SHARES_PER_SET)))
    .unwrap()
  {
    validators[validators.len() - ((i % validators.len()) + 1)].1 -= 1;
  }
}
