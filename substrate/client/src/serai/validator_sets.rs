use sp_core::sr25519::{Public, Signature};

use serai_runtime::{primitives::Amount, validator_sets, ValidatorSets, Runtime};
pub use validator_sets::primitives;
use primitives::{Session, ValidatorSet, KeyPair};

use subxt::utils::Encoded;

use crate::{primitives::NetworkId, Serai, SeraiError, scale_value};

const PALLET: &str = "ValidatorSets";

pub type ValidatorSetsEvent = validator_sets::Event<Runtime>;

impl Serai {
  pub async fn get_new_set_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .events::<ValidatorSets, _>(block, |event| matches!(event, ValidatorSetsEvent::NewSet { .. }))
      .await
  }

  pub async fn get_key_gen_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .events::<ValidatorSets, _>(block, |event| matches!(event, ValidatorSetsEvent::KeyGen { .. }))
      .await
  }

  pub async fn get_session(
    &self,
    network: NetworkId,
    at_hash: [u8; 32],
  ) -> Result<Option<Session>, SeraiError> {
    self.storage(PALLET, "CurrentSession", Some(vec![scale_value(network)]), at_hash).await
  }

  pub async fn get_validator_set_participants(
    &self,
    network: NetworkId,
    at_hash: [u8; 32],
  ) -> Result<Option<Vec<Public>>, SeraiError> {
    self.storage(PALLET, "Participants", Some(vec![scale_value(network)]), at_hash).await
  }

  pub async fn get_allocation_per_key_share(
    &self,
    network: NetworkId,
    at_hash: [u8; 32],
  ) -> Result<Option<Amount>, SeraiError> {
    self.storage(PALLET, "AllocationPerKeyShare", Some(vec![scale_value(network)]), at_hash).await
  }

  pub async fn get_allocation(
    &self,
    network: NetworkId,
    key: Public,
    at_hash: [u8; 32],
  ) -> Result<Option<Amount>, SeraiError> {
    self.storage(PALLET, "Allocations", Some(vec![scale_value(network), scale_value(key)]), at_hash).await
  }

  pub async fn get_validator_set_musig_key(
    &self,
    set: ValidatorSet,
    at_hash: [u8; 32],
  ) -> Result<Option<[u8; 32]>, SeraiError> {
    self.storage(PALLET, "MuSigKeys", Some(vec![scale_value(set)]), at_hash).await
  }

  // TODO: Store these separately since we almost never need both at once?
  pub async fn get_keys(
    &self,
    set: ValidatorSet,
    at_hash: [u8; 32],
  ) -> Result<Option<KeyPair>, SeraiError> {
    self.storage(PALLET, "Keys", Some(vec![scale_value(set)]), at_hash).await
  }

  pub fn set_validator_set_keys(
    network: NetworkId,
    key_pair: KeyPair,
    signature: Signature,
  ) -> Encoded {
    Self::unsigned::<ValidatorSets, _>(&validator_sets::Call::<Runtime>::set_keys {
      network,
      key_pair,
      signature,
    })
  }
}
