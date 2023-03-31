use serai_runtime::{validator_sets, ValidatorSets, Runtime};
pub use validator_sets::primitives;
use primitives::{ValidatorSet, ValidatorSetData, KeyPair};

use subxt::tx::{self, DynamicTxPayload};

use crate::{primitives::NetworkId, Serai, SeraiError, scale_value, scale_composite};

const PALLET: &str = "ValidatorSets";

pub type ValidatorSetsEvent = validator_sets::Event<Runtime>;

impl Serai {
  pub async fn get_vote_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .events::<ValidatorSets, _>(block, |event| matches!(event, ValidatorSetsEvent::Vote { .. }))
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

  pub async fn get_keys(&self, set: ValidatorSet) -> Result<Option<KeyPair>, SeraiError> {
    self
      .storage(PALLET, "Keys", Some(vec![scale_value(set)]), self.get_latest_block_hash().await?)
      .await
  }

  pub fn vote(network: NetworkId, key_pair: KeyPair) -> DynamicTxPayload<'static> {
    tx::dynamic(
      PALLET,
      "vote",
      scale_composite(validator_sets::Call::<Runtime>::vote { network, key_pair }),
    )
  }
}
