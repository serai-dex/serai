use sp_core::sr25519::Signature;

use serai_runtime::{validator_sets, ValidatorSets, Runtime};
pub use validator_sets::primitives;
use primitives::{ValidatorSet, ValidatorSetData, KeyPair};

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

  pub async fn get_validator_set(
    &self,
    set: ValidatorSet,
  ) -> Result<Option<ValidatorSetData>, SeraiError> {
    self
      .storage(
        PALLET,
        "ValidatorSets",
        Some(vec![scale_value(set)]),
        self.get_latest_block_hash().await?,
      )
      .await
  }

  pub async fn get_validator_set_musig_key(
    &self,
    set: ValidatorSet,
  ) -> Result<Option<[u8; 32]>, SeraiError> {
    self
      .storage(
        PALLET,
        "MuSigKeys",
        Some(vec![scale_value(set)]),
        self.get_latest_block_hash().await?,
      )
      .await
  }

  // TODO: Store these separately since we almost never need both at once?
  pub async fn get_keys(&self, set: ValidatorSet) -> Result<Option<KeyPair>, SeraiError> {
    self
      .storage(PALLET, "Keys", Some(vec![scale_value(set)]), self.get_latest_block_hash().await?)
      .await
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
