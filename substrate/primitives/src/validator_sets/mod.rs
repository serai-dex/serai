use alloc::{vec, vec::Vec};

use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::{group::GroupEncoding as _, GroupIo};
use dalek_ff_group::Ristretto;

use sp_core::sr25519::Public;

use crate::{
  crypto::KeyPair,
  network_id::{ExternalNetworkId, NetworkId},
};

mod key_shares;
pub use key_shares::*;

mod slashes;
pub use slashes::*;

/// The type used to identify a specific session of validators.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Session(pub u32);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Session);

/// The type used to identify a specific set of validators for an external network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct ExternalValidatorSet {
  /// The network this set of validators are for.
  pub network: ExternalNetworkId,
  /// Which session this set of validators is occuring during.
  pub session: Session,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ExternalValidatorSet);
#[cfg(feature = "scale")]
impl scale::EncodeLike<ValidatorSet> for ExternalValidatorSet {}

/// The type used to identify a specific set of validators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct ValidatorSet {
  /// The network this set of validators are for.
  pub network: NetworkId,
  /// Which session this set of validators is occuring during.
  pub session: Session,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(ValidatorSet);

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

/// An error from [`ValidatorSet::musig_key`].
#[derive(Debug)]
pub enum MusigKeyError {
  /// An invalid key was provided.
  InvalidKey,
  /// No keys were provided.
  NoKeysProvided,
  /// Too many keys were provided.
  TooManyKeysProvided,
}

impl ValidatorSet {
  /// The MuSig context for this validator set.
  pub fn musig_context(&self) -> [u8; 32] {
    sp_core::blake2_256(&borsh::to_vec(&(b"ValidatorSets-musig_key", self)).unwrap())
  }

  /// The MuSig public key for a validator set.
  ///
  /// Because [`dkg-musig`] rejects duplicate keys present within a MuSig-aggregated key, this
  /// function filters keys such that only the _first_ presence of a key is preserved. Later
  /// presences will be omitted. As MuSig produces an `n`-of-`n` access structure, this does not
  /// change which private keys must be known to sign with the resulting key.
  pub fn musig_key(&self, keys: &[Public]) -> Result<Public, MusigKeyError> {
    let mut deduplicated_keys = vec![];
    {
      let mut seen_keys = alloc::collections::BTreeSet::new();
      for key in keys {
        if seen_keys.insert(key) {
          deduplicated_keys.push(key);
        }
      }
    }

    let mut decompressed_keys = vec![];
    for key in deduplicated_keys {
      decompressed_keys.push(
        <Ristretto as GroupIo>::read_G(key.0.as_slice()).map_err(|_| MusigKeyError::InvalidKey)?,
      );
    }

    match dkg::musig_key_vartime::<Ristretto>(self.musig_context(), &decompressed_keys) {
      Ok(key) => Ok(key.to_bytes().into()),
      Err(e) => Err(match e {
        dkg::MusigKeyError::NoKeysProvided => MusigKeyError::NoKeysProvided,
        dkg::MusigKeyError::TooManyKeysProvided { .. } => MusigKeyError::TooManyKeysProvided,
        dkg::MusigKeyError::DuplicatedParticipant(_) => {
          unreachable!("function de-duplicated keys before calling underlying")
        }
      }),
    }
  }
}

impl ExternalValidatorSet {
  /// The message for the `set_keys` signature.
  pub fn set_keys_message(&self, key_pair: &KeyPair) -> Vec<u8> {
    borsh::to_vec(&(b"ValidatorSets-set_keys", self, key_pair)).unwrap()
  }
}

/// The timeline for a deallocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum DeallocationTimeline {
  /// The deallocation is available immediately.
  Immediate,
  /// The dealocation was delayed.
  Delayed {
    /// The session the deallocation unlocks at and can be claimed.
    unlocks_at: Session,
  },
}

#[test]
fn session() {
  assert_eq!(Session(0), Session(0));
  assert!(Session(0) != Session(1));
  assert!(Session(0) < Session(1));
  assert!(Session(1) > Session(0));

  use rand_core::{RngCore as _, OsRng};

  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  let session = Session(OsRng.next_u64() as u32);

  assert_eq!(
    Session::deserialize_reader(&mut borsh::to_vec(&session).unwrap().as_slice()).unwrap(),
    session
  );

  #[cfg(feature = "scale")]
  {
    use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
    assert_eq!(session.encode(), borsh::to_vec(&session).unwrap());
    assert_eq!(Session::decode_all(&mut session.encode().as_slice()).unwrap(), session);
    assert_eq!(Session(u32::MAX).encode().len(), Session::max_encoded_len());
  }
}

#[test]
fn external_validator_set() {
  use rand_core::{RngCore as _, OsRng};

  for network in ExternalNetworkId::all() {
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    let session = Session(OsRng.next_u64() as u32);
    let validator_set = ExternalValidatorSet { network, session };
    assert_eq!(
      ExternalValidatorSet::try_from(ValidatorSet::from(validator_set)).unwrap(),
      validator_set
    );

    assert_eq!(
      ExternalValidatorSet::deserialize_reader(
        &mut borsh::to_vec(&validator_set).unwrap().as_slice()
      )
      .unwrap(),
      validator_set
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
      assert_eq!(validator_set.encode(), borsh::to_vec(&validator_set).unwrap());
      assert_eq!(
        ExternalValidatorSet::decode_all(&mut validator_set.encode().as_slice()).unwrap(),
        validator_set
      );
      assert_eq!(ValidatorSet::from(validator_set).encode(), validator_set.encode());
      assert_eq!(
        (ExternalValidatorSet { network, session: Session(u32::MAX) }).encode().len(),
        ExternalValidatorSet::max_encoded_len()
      );
    }
  }
}

#[test]
fn validator_set() {
  use rand_core::{RngCore as _, OsRng};

  for network in NetworkId::all() {
    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    let session = Session(OsRng.next_u64() as u32);
    let validator_set = ValidatorSet { network, session };

    assert_eq!(
      ValidatorSet::deserialize_reader(&mut borsh::to_vec(&validator_set).unwrap().as_slice())
        .unwrap(),
      validator_set
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
      assert_eq!(validator_set.encode(), borsh::to_vec(&validator_set).unwrap());
      assert_eq!(
        ValidatorSet::decode_all(&mut validator_set.encode().as_slice()).unwrap(),
        validator_set
      );
      assert_eq!(
        (ValidatorSet { network, session: Session(u32::MAX) }).encode().len(),
        ValidatorSet::max_encoded_len()
      );
    }
  }
}

#[test]
fn musig_key() {
  use ciphersuite::WrappedGroup as _;
  let key1 = dalek_ff_group::Ristretto::generator();
  let key2 = key1 + key1;
  let key3 = key2 + key1;

  let key1 = key1.to_bytes().into();
  let key2 = key2.to_bytes().into();
  let key3 = key3.to_bytes().into();

  let keys = vec![key1, key2, key1, key3];
  let deduplicated_keys = vec![key1, key2, key3];
  let set = ValidatorSet { network: NetworkId::Serai, session: Session(0) };
  assert_eq!(set.musig_key(&keys).unwrap(), set.musig_key(&deduplicated_keys).unwrap());
}
