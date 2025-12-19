use core::str::FromStr as _;

use borsh::BorshDeserialize as _;

pub use serai_abi::{
  primitives::{
    crypto::{Signature, KeyPair, EmbeddedEllipticCurveKeys},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ExternalValidatorSet, SlashReport},
    balance::Amount,
    address::SeraiAddress,
  },
  validator_sets::{Call, Event},
  UnsignedCall, Transaction,
};

use crate::{RpcError, Events, State};

fn rpc_network(network: impl Into<NetworkId>) -> &'static str {
  match network.into() {
    NetworkId::Serai => r#""serai""#,
    NetworkId::External(ExternalNetworkId::Bitcoin) => r#""bitcoin""#,
    NetworkId::External(ExternalNetworkId::Ethereum) => r#""ethereum""#,
    NetworkId::External(ExternalNetworkId::Monero) => r#""monero""#,
  }
}

/// An `Events` scoped to the validator sets module.
#[derive(Clone)]
pub struct ValidatorSets(pub(super) Events);

impl ValidatorSets {
  /// The events from the validator sets module.
  pub fn events(&self) -> impl Iterator<Item = &Event> {
    #[expect(clippy::wildcard_enum_match_arm)]
    self.0.events().flatten().filter_map(|event| match event {
      serai_abi::Event::ValidatorSets(event) => Some(event),
      _ => None,
    })
  }

  /// The `SetDecided` events from the validator sets module.
  pub fn set_decided_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::SetDecided { .. }))
  }

  /// The `SetKeys` events from the validator sets module.
  pub fn set_keys_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::SetKeys { .. }))
  }

  /// The `AcceptedHandover` events from the validator sets module.
  pub fn accepted_handover_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::AcceptedHandover { .. }))
  }

  /// The `SlashReport` events from the validator sets module.
  pub fn slash_report_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::SlashReport { .. }))
  }

  /// The `SetEmbeddedEllipticCurveKeys` events from the validator sets module.
  pub fn set_embedded_elliptic_curve_keys_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::SetEmbeddedEllipticCurveKeys { .. }))
  }

  /// The `Allocation` events from the validator sets module.
  pub fn allocation_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Allocation { .. }))
  }

  /// The `Deallocation` events from the validator sets module.
  pub fn deallocation_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::Deallocation { .. }))
  }

  /// The `DelayedDeallocationClaimed` events from the validator sets module.
  pub fn delayed_deallocation_claimed_events(&self) -> impl Iterator<Item = &Event> {
    self.events().filter(|event| matches!(event, Event::DelayedDeallocationClaimed { .. }))
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

impl State<'_> {
  /// The current session for the specified network.
  pub async fn current_session(&self, network: NetworkId) -> Result<Option<Session>, RpcError> {
    Ok(
      self
        .call::<Option<_>>(
          "validator-sets/current_session",
          &format!(r#", "network": {} "#, rpc_network(network)),
        )
        .await?
        .map(Session),
    )
  }

  /// The stake for the current validators for the specified network.
  pub async fn current_stake(&self, network: NetworkId) -> Result<Option<Amount>, RpcError> {
    Ok(
      self
        .call::<Option<_>>(
          "validator-sets/current_stake",
          &format!(r#", "network": {} "#, rpc_network(network)),
        )
        .await?
        .map(Amount),
    )
  }

  /// The keys for the specified validator set.
  pub async fn keys(&self, set: ExternalValidatorSet) -> Result<Option<KeyPair>, RpcError> {
    let Some(key_pair) = self
      .call::<Option<String>>(
        "validator-sets/keys",
        &format!(r#", "network": {}, "session": {} "#, rpc_network(set.network), set.session.0),
      )
      .await?
    else {
      return Ok(None);
    };
    KeyPair::deserialize(
      &mut hex::decode(key_pair)
        .map_err(|_| RpcError::InvalidNode("validator set's keys weren't valid hex".to_owned()))?
        .as_slice(),
    )
    .map(Some)
    .map_err(|_| RpcError::InvalidNode("validator set's keys weren't a valid key pair".to_owned()))
  }

  /// The current validators for the specified network.
  pub async fn current_validators(
    &self,
    network: NetworkId,
  ) -> Result<Option<Vec<SeraiAddress>>, RpcError> {
    self
      .call::<Option<Vec<String>>>(
        "validator-sets/current_validators",
        &format!(r#", "network": {} "#, rpc_network(network)),
      )
      .await?
      .map(|validators| {
        validators
          .into_iter()
          .map(|addr| {
            SeraiAddress::from_str(&addr)
              .map_err(|_| RpcError::InvalidNode("validator's address was invalid".to_owned()))
          })
          .collect()
      })
      .transpose()
  }

  /// If the prior validators for this network is still expected to publish a slash report.
  pub async fn pending_slash_report(&self, network: ExternalNetworkId) -> Result<bool, RpcError> {
    self
      .call(
        "validator-sets/pending_slash_report",
        &format!(r#", "network": {} "#, rpc_network(network)),
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
      .call::<Option<String>>(
        "validator-sets/embedded_elliptic_curve_keys",
        &format!(r#", "validator": "{validator}", "network": {} "#, rpc_network(network)),
      )
      .await?
    else {
      return Ok(None);
    };
    EmbeddedEllipticCurveKeys::deserialize(
      &mut hex::decode(keys)
        .map_err(|_| {
          RpcError::InvalidNode(
            "validator's embedded elliptic curve keys weren't valid hex".to_owned(),
          )
        })?
        .as_slice(),
    )
    .map(Some)
    .map_err(|_| {
      RpcError::InvalidNode("validator's embedded elliptic curve keys weren't valid".to_owned())
    })
  }
}
