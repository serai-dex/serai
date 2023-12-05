use scale::Encode;

use sp_core::sr25519::{Public, Signature};

use serai_runtime::{primitives::Amount, validator_sets, Runtime};
pub use validator_sets::primitives;
use primitives::{Session, ValidatorSet, KeyPair};

use crate::{primitives::NetworkId, Serai, TemporalSerai, SeraiError};

const PALLET: &str = "ValidatorSets";

pub type ValidatorSetsEvent = validator_sets::Event<Runtime>;

#[derive(Clone, Copy)]
pub struct SeraiValidatorSets<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiValidatorSets<'a> {
  pub fn into_inner(self) -> TemporalSerai<'a> {
    self.0
  }

  pub async fn new_set_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_runtime::RuntimeEvent::ValidatorSets(event) = event {
          Some(event).filter(|event| matches!(event, ValidatorSetsEvent::NewSet { .. }))
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
        if let serai_runtime::RuntimeEvent::ValidatorSets(event) = event {
          Some(event).filter(|event| matches!(event, ValidatorSetsEvent::KeyGen { .. }))
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
        if let serai_runtime::RuntimeEvent::ValidatorSets(event) = event {
          Some(event).filter(|event| matches!(event, ValidatorSetsEvent::SetRetired { .. }))
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

  pub fn set_keys(network: NetworkId, key_pair: KeyPair, signature: Signature) -> Vec<u8> {
    Serai::unsigned(&serai_runtime::RuntimeCall::ValidatorSets(
      validator_sets::Call::<Runtime>::set_keys { network, key_pair, signature },
    ))
  }

  pub fn remove_participant(
    network: NetworkId,
    to_remove: Public,
    signers: Vec<Public>,
    signature: Signature,
  ) -> Vec<u8> {
    Serai::unsigned(&serai_runtime::RuntimeCall::ValidatorSets(
      validator_sets::Call::<Runtime>::remove_participant {
        network,
        to_remove,
        signers,
        signature,
      },
    ))
  }
}
