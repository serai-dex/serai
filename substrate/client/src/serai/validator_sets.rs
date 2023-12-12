use scale::Encode;

use sp_core::sr25519::{Public, Signature};

use serai_abi::primitives::Amount;
pub use serai_abi::validator_sets::primitives;
use primitives::{Session, ValidatorSet, KeyPair};

use crate::{
  primitives::{NetworkId, SeraiAddress},
  Transaction, Serai, TemporalSerai, SeraiError,
};

const PALLET: &str = "ValidatorSets";

pub type ValidatorSetsEvent = serai_abi::validator_sets::Event;

#[derive(Clone, Copy)]
pub struct SeraiValidatorSets<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiValidatorSets<'a> {
  pub async fn new_set_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::ValidatorSets(event) = event {
          if matches!(event, ValidatorSetsEvent::NewSet { .. }) {
            Some(event.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .await
  }

  pub async fn participant_removed_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::ValidatorSets(event) = event {
          if matches!(event, ValidatorSetsEvent::ParticipantRemoved { .. }) {
            Some(event.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .await
  }

  pub async fn key_gen_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::ValidatorSets(event) = event {
          if matches!(event, ValidatorSetsEvent::KeyGen { .. }) {
            Some(event.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .await
  }

  pub async fn set_retired_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::ValidatorSets(event) = event {
          if matches!(event, ValidatorSetsEvent::SetRetired { .. }) {
            Some(event.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .await
  }

  pub async fn session(&self, network: NetworkId) -> Result<Option<Session>, SeraiError> {
    self.0.storage(PALLET, "CurrentSession", network).await
  }

  pub async fn participants(
    &self,
    network: NetworkId,
  ) -> Result<Option<Vec<(Public, u64)>>, SeraiError> {
    self.0.storage(PALLET, "Participants", network).await
  }

  pub async fn allocation_per_key_share(
    &self,
    network: NetworkId,
  ) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "AllocationPerKeyShare", network).await
  }

  pub async fn total_allocated_stake(
    &self,
    network: NetworkId,
  ) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "TotalAllocatedStake", network).await
  }

  pub async fn allocation(
    &self,
    network: NetworkId,
    key: Public,
  ) -> Result<Option<Amount>, SeraiError> {
    self
      .0
      .storage(
        PALLET,
        "Allocations",
        (sp_core::hashing::blake2_128(&(network, key).encode()), (network, key)),
      )
      .await
  }

  pub async fn musig_key(&self, set: ValidatorSet) -> Result<Option<[u8; 32]>, SeraiError> {
    self.0.storage(PALLET, "MuSigKeys", (sp_core::hashing::twox_64(&set.encode()), set)).await
  }

  // TODO: Store these separately since we almost never need both at once?
  pub async fn keys(&self, set: ValidatorSet) -> Result<Option<KeyPair>, SeraiError> {
    self.0.storage(PALLET, "Keys", (sp_core::hashing::twox_64(&set.encode()), set)).await
  }

  pub fn set_keys(network: NetworkId, key_pair: KeyPair, signature: Signature) -> Transaction {
    Serai::unsigned(serai_abi::Call::ValidatorSets(serai_abi::validator_sets::Call::set_keys {
      network,
      key_pair,
      signature,
    }))
  }

  pub fn remove_participant(
    network: NetworkId,
    to_remove: SeraiAddress,
    signers: Vec<SeraiAddress>,
    signature: Signature,
  ) -> Transaction {
    Serai::unsigned(serai_abi::Call::ValidatorSets(
      serai_abi::validator_sets::Call::remove_participant {
        network,
        to_remove,
        signers,
        signature,
      },
    ))
  }
}
