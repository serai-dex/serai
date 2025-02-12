use alloc::vec::Vec;

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use crate::{
  crypto::{Public, KeyPair},
  network_id::{ExternalNetworkId, NetworkId},
};

mod slashes;
pub use slashes::*;

/// The type used to identify a specific session of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct Session(pub u32);

/// The type used to identify a specific set of validators for an external network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct ExternalValidatorSet {
  /// The network this set of validators are for.
  pub network: ExternalNetworkId,
  /// Which session this set of validators is occuring during.
  pub session: Session,
}

/// The type used to identify a specific set of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
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
  pub fn musig_context(&self) -> Vec<u8> {
    borsh::to_vec(&(b"ValidatorSets-musig_key".as_ref(), self)).unwrap()
  }

  /// The MuSig public key for a validator set.
  ///
  /// This function panics on invalid input, per the definition of `dkg::musig::musig_key`.
  pub fn musig_key(&self, set_keys: &[Public]) -> Public {
    let mut keys = Vec::new();
    for key in set_keys {
      keys.push(
        <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut key.0.as_ref())
          .expect("invalid participant"),
      );
    }
    Public(dkg::musig::musig_key::<Ristretto>(&self.musig_context(), &keys).unwrap().to_bytes())
  }

  /// The message for the `set_keys` signature.
  pub fn set_keys_message(&self, key_pair: &KeyPair) -> Vec<u8> {
    borsh::to_vec(&(b"ValidatorSets-set_keys", self, key_pair)).unwrap()
  }
}
