use borsh::BorshDeserialize;

pub use serai_abi::{
  primitives::{
    crypto::KeyPair,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ExternalValidatorSet, ValidatorSet},
    balance::Amount,
  },
  validator_sets::Event,
};

use crate::{RpcError, TemporalSerai};

fn rpc_network(network: impl Into<NetworkId>) -> Result<&'static str, RpcError> {
  Ok(match network.into() {
    NetworkId::Serai => r#""serai""#,
    NetworkId::External(ExternalNetworkId::Bitcoin) => r#""bitcoin""#,
    NetworkId::External(ExternalNetworkId::Ethereum) => r#""ethereum""#,
    NetworkId::External(ExternalNetworkId::Monero) => r#""monero""#,
    _ => Err(RpcError::InternalError("unrecognized network ID".to_string()))?,
  })
}

/// A `TemporalSerai` scoped to the validator sets module.
#[derive(Clone)]
pub struct ValidatorSets<'a>(pub(super) &'a TemporalSerai<'a>);

impl<'a> ValidatorSets<'a> {
  /// The events from the validator sets module.
  pub async fn events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .0
        .events()
        .await?
        .as_ref()
        .expect("`TemporalSerai::events` returned None")
        .iter()
        .filter_map(|event| match event {
          serai_abi::Event::ValidatorSets(event) => Some(event.clone()),
          _ => None,
        })
        .collect(),
    )
  }

  /// The `SetDecided` events from the validator sets module.
  pub async fn set_decided_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::SetDecided { .. }))
        .collect(),
    )
  }

  /// The `SetKeys` events from the validator sets module.
  pub async fn set_keys_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::SetKeys { .. }))
        .collect(),
    )
  }

  /// The `AcceptedHandover` events from the validator sets module.
  pub async fn accepted_handover_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::AcceptedHandover { .. }))
        .collect(),
    )
  }

  /// The `SlashReport` events from the validator sets module.
  pub async fn slash_report_events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .events()
        .await?
        .into_iter()
        .filter(|event| matches!(event, Event::SlashReport { .. }))
        .collect(),
    )
  }

  /// The current session for the specified network.
  pub async fn current_session(&self, network: NetworkId) -> Result<Option<Session>, RpcError> {
    Ok(
      self
        .0
        .call::<Option<_>>(
          "validator-sets/session",
          &format!(r#" "network": {} "#, rpc_network(network)?),
        )
        .await?
        .map(Session),
    )
  }

  /// The stake for the current validators for specified network.
  pub async fn current_stake(&self, network: NetworkId) -> Result<Option<Amount>, RpcError> {
    Ok(
      self
        .0
        .call::<Option<_>>(
          "validator-sets/current_stake",
          &format!(r#" "network": {} "#, rpc_network(network)?),
        )
        .await?
        .map(Amount),
    )
  }

  /// The keys for the specified validator set.
  pub async fn keys(&self, set: ExternalValidatorSet) -> Result<Option<KeyPair>, RpcError> {
    let Some(key_pair) = self
      .0
      .call::<Option<String>>(
        "validator-sets/keys",
        &format!(
          r#" "set": {{ "network": {}, "session": {} }} "#,
          rpc_network(set.network)?,
          set.session.0
        ),
      )
      .await?
    else {
      return Ok(None);
    };
    KeyPair::deserialize(
      &mut hex::decode(key_pair)
        .map_err(|_| RpcError::InvalidNode("validator set's keys weren't valid hex".to_string()))?
        .as_slice(),
    )
    .map(Some)
    .map_err(|_| RpcError::InvalidNode("validator set's keys weren't a valid key pair".to_string()))
  }
}
