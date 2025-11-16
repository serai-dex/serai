use core::str::FromStr;

use borsh::BorshDeserialize;

pub use serai_abi::{
  primitives::{
    crypto::{Signature, KeyPair, EmbeddedEllipticCurveKeys},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ExternalValidatorSet, ValidatorSet, SlashReport},
    balance::Amount,
    address::SeraiAddress,
  },
  validator_sets::{Call, Event},
  UnsignedCall, Transaction,
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
pub struct ValidatorSets<'serai>(pub(super) &'serai TemporalSerai<'serai>);

impl<'serai> ValidatorSets<'serai> {
  /// The events from the validator sets module.
  pub async fn events(&self) -> Result<Vec<Event>, RpcError> {
    Ok(
      self
        .0
        .events_borrowed()
        .await?
        .as_ref()
        .expect("`TemporalSerai::events` returned None")
        .iter()
        .flat_map(IntoIterator::into_iter)
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
          "validator-sets/current_session",
          &format!(r#", "network": {} "#, rpc_network(network)?),
        )
        .await?
        .map(Session),
    )
  }

  /// The stake for the current validators for the specified network.
  pub async fn current_stake(&self, network: NetworkId) -> Result<Option<Amount>, RpcError> {
    Ok(
      self
        .0
        .call::<Option<_>>(
          "validator-sets/current_stake",
          &format!(r#", "network": {} "#, rpc_network(network)?),
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
        &format!(r#", "network": {}, "session": {} "#, rpc_network(set.network)?, set.session.0),
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

  /// The current validators for the specified network.
  pub async fn current_validators(
    &self,
    network: NetworkId,
  ) -> Result<Option<Vec<SeraiAddress>>, RpcError> {
    self
      .0
      .call::<Option<Vec<String>>>(
        "validator-sets/current_validators",
        &format!(r#", "network": {} "#, rpc_network(network)?),
      )
      .await?
      .map(|validators| {
        validators
          .into_iter()
          .map(|addr| {
            SeraiAddress::from_str(&addr)
              .map_err(|_| RpcError::InvalidNode("validator's address was invalid".to_string()))
          })
          .collect()
      })
      .transpose()
  }

  /// If the prior validators for this network is still expected to publish a slash report.
  pub async fn pending_slash_report(&self, network: ExternalNetworkId) -> Result<bool, RpcError> {
    self
      .0
      .call(
        "validator-sets/pending_slash_report",
        &format!(r#", "network": {} "#, rpc_network(network)?),
      )
      .await
  }

  /// The key on an embedded elliptic curve for the specified validator.
  pub async fn embedded_elliptic_curve_keys(
    &self,
    validator: SeraiAddress,
    network: ExternalNetworkId,
  ) -> Result<Option<EmbeddedEllipticCurveKeys>, RpcError> {
    let Some(keys) = self
      .0
      .call::<Option<String>>(
        "validator-sets/embedded_elliptic_curve_keys",
        &format!(r#", "validator": {validator}, "network": {} "#, rpc_network(network)?),
      )
      .await?
    else {
      return Ok(None);
    };
    EmbeddedEllipticCurveKeys::deserialize(
      &mut hex::decode(keys)
        .map_err(|_| {
          RpcError::InvalidNode(
            "validator's embedded elliptic curve keys weren't valid hex".to_string(),
          )
        })?
        .as_slice(),
    )
    .map(Some)
    .map_err(|_| {
      RpcError::InvalidNode("validator's embedded elliptic curve keys weren't valid".to_string())
    })
  }

  /// Create a transaction to set a validator set's keys.
  pub fn set_keys(
    network: ExternalNetworkId,
    key_pair: KeyPair,
    signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
    signature: Signature,
  ) -> Transaction {
    Transaction::Unsigned {
      call: UnsignedCall::try_from(serai_abi::Call::from(Call::set_keys {
        network,
        key_pair,
        signature_participants,
        signature,
      }))
      .expect("`set_keys` wasn't an unsigned call?"),
    }
  }

  /// Create a transaction to report the slashes for a validator set.
  pub fn report_slashes(
    network: ExternalNetworkId,
    slashes: SlashReport,
    signature: Signature,
  ) -> Transaction {
    Transaction::Unsigned {
      call: UnsignedCall::try_from(serai_abi::Call::from(Call::report_slashes {
        network,
        slashes,
        signature,
      }))
      .expect("`report_slashes` wasn't an unsigned call?"),
    }
  }
}
