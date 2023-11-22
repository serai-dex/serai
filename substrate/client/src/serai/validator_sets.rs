use sp_core::sr25519::{Public, Signature};

use serai_runtime::{primitives::Amount, validator_sets, ValidatorSets, Runtime};
pub use validator_sets::primitives;
use primitives::{Session, ValidatorSet, KeyPair};

use subxt::utils::Encoded;

use crate::{primitives::NetworkId, Serai, TemporalSerai, SeraiError, scale_value};

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
      .events::<ValidatorSets, _>(|event| matches!(event, ValidatorSetsEvent::NewSet { .. }))
      .await
  }

  pub async fn key_gen_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events::<ValidatorSets, _>(|event| matches!(event, ValidatorSetsEvent::KeyGen { .. }))
      .await
  }

  pub async fn set_retired_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events::<ValidatorSets, _>(|event| matches!(event, ValidatorSetsEvent::SetRetired { .. }))
      .await
  }

  pub async fn session(&self, network: NetworkId) -> Result<Option<Session>, SeraiError> {
    self.0.storage(PALLET, "CurrentSession", Some(vec![scale_value(network)])).await
  }

  pub async fn participants(
    &self,
    network: NetworkId,
  ) -> Result<Option<Vec<(Public, u64)>>, SeraiError> {
    self.0.storage(PALLET, "Participants", Some(vec![scale_value(network)])).await
  }

  pub async fn allocation_per_key_share(
    &self,
    network: NetworkId,
  ) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "AllocationPerKeyShare", Some(vec![scale_value(network)])).await
  }

  pub async fn total_allocated_stake(
    &self,
    network: NetworkId,
  ) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "TotalAllocatedStake", Some(vec![scale_value(network)])).await
  }

  pub async fn allocation(
    &self,
    network: NetworkId,
    key: Public,
  ) -> Result<Option<Amount>, SeraiError> {
    self.0.storage(PALLET, "Allocations", Some(vec![scale_value(network), scale_value(key)])).await
  }

  pub async fn musig_key(&self, set: ValidatorSet) -> Result<Option<[u8; 32]>, SeraiError> {
    self.0.storage(PALLET, "MuSigKeys", Some(vec![scale_value(set)])).await
  }

  // TODO: Store these separately since we almost never need both at once?
  pub async fn keys(&self, set: ValidatorSet) -> Result<Option<KeyPair>, SeraiError> {
    self.0.storage(PALLET, "Keys", Some(vec![scale_value(set)])).await
  }

  pub fn set_keys(network: NetworkId, key_pair: KeyPair, signature: Signature) -> Encoded {
    Serai::unsigned::<ValidatorSets, _>(&validator_sets::Call::<Runtime>::set_keys {
      network,
      key_pair,
      signature,
    })
  }
}
