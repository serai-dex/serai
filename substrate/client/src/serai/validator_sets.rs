use scale::Encode;

use sp_core::sr25519::{Public, Signature};
use sp_runtime::BoundedVec;

use serai_abi::primitives::Amount;
pub use serai_abi::validator_sets::primitives;
use primitives::{MAX_KEY_LEN, Session, ValidatorSet, KeyPair};

use crate::{
  primitives::{EmbeddedEllipticCurve, NetworkId, SeraiAddress},
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

  pub async fn accepted_handover_events(&self) -> Result<Vec<ValidatorSetsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::ValidatorSets(event) = event {
          if matches!(event, ValidatorSetsEvent::AcceptedHandover { .. }) {
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

  pub async fn embedded_elliptic_curve_key(
    &self,
    validator: Public,
    embedded_elliptic_curve: EmbeddedEllipticCurve,
  ) -> Result<Option<Vec<u8>>, SeraiError> {
    self
      .0
      .storage(
        PALLET,
        "EmbeddedEllipticCurveKeys",
        (sp_core::hashing::blake2_128(&validator.encode()), validator, embedded_elliptic_curve),
      )
      .await
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

  pub async fn pending_deallocations(
    &self,
    network: NetworkId,
    account: Public,
    session: Session,
  ) -> Result<Option<Amount>, SeraiError> {
    self
      .0
      .storage(
        PALLET,
        "PendingDeallocations",
        (sp_core::hashing::blake2_128(&(network, account).encode()), (network, account, session)),
      )
      .await
  }

  pub async fn active_network_validators(
    &self,
    network: NetworkId,
  ) -> Result<Vec<Public>, SeraiError> {
    self.0.runtime_api("SeraiRuntimeApi_validators", network).await
  }

  // TODO: Store these separately since we almost never need both at once?
  pub async fn keys(&self, set: ValidatorSet) -> Result<Option<KeyPair>, SeraiError> {
    self.0.storage(PALLET, "Keys", (sp_core::hashing::twox_64(&set.encode()), set)).await
  }

  pub async fn key_pending_slash_report(
    &self,
    network: NetworkId,
  ) -> Result<Option<Public>, SeraiError> {
    self.0.storage(PALLET, "PendingSlashReport", network).await
  }

  pub async fn session_begin_block(
    &self,
    network: NetworkId,
    session: Session,
  ) -> Result<Option<u64>, SeraiError> {
    self.0.storage(PALLET, "SessionBeginBlock", (network, session)).await
  }

  pub fn set_keys(
    network: NetworkId,
    key_pair: KeyPair,
    signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
    signature: Signature,
  ) -> Transaction {
    Serai::unsigned(serai_abi::Call::ValidatorSets(serai_abi::validator_sets::Call::set_keys {
      network,
      key_pair,
      signature_participants,
      signature,
    }))
  }

  pub fn set_embedded_elliptic_curve_key(
    embedded_elliptic_curve: EmbeddedEllipticCurve,
    key: BoundedVec<u8, sp_core::ConstU32<{ MAX_KEY_LEN }>>,
  ) -> serai_abi::Call {
    serai_abi::Call::ValidatorSets(
      serai_abi::validator_sets::Call::set_embedded_elliptic_curve_key {
        embedded_elliptic_curve,
        key,
      },
    )
  }

  pub fn allocate(network: NetworkId, amount: Amount) -> serai_abi::Call {
    serai_abi::Call::ValidatorSets(serai_abi::validator_sets::Call::allocate { network, amount })
  }

  pub fn deallocate(network: NetworkId, amount: Amount) -> serai_abi::Call {
    serai_abi::Call::ValidatorSets(serai_abi::validator_sets::Call::deallocate { network, amount })
  }

  pub fn report_slashes(
    network: NetworkId,
    slashes: sp_runtime::BoundedVec<
      (SeraiAddress, u32),
      sp_core::ConstU32<{ primitives::MAX_KEY_SHARES_PER_SET / 3 }>,
    >,
    signature: Signature,
  ) -> Transaction {
    Serai::unsigned(serai_abi::Call::ValidatorSets(
      serai_abi::validator_sets::Call::report_slashes { network, slashes, signature },
    ))
  }
}
