//! Ephemeral events, which only need to be handled by the validators
//! present within the sets they relate to.
//!
//! Depends on cosigned blocks, on halt does not send new messages to the processor.
use core::future::Future;
use std::sync::Arc;
use ciphersuite::{group::GroupEncoding as _, WrappedGroup};
use dalek_ff_group::Ristretto;

use serai_client_serai::{
  abi::primitives::{
    BlockHash,
    crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
    validator_sets::{KeyShares, ExternalValidatorSet},
  },
  Serai, Events,
};

use serai_db::*;
use serai_primitives::address::SeraiAddress;
use serai_tributary_types::{TributaryValidatorSet, TributaryValidator};
use serai_task::{ContinuallyRan, FuturesRangeProcessor};

use serai_cosign::Cosigning;

use crate::TributaryValidatorSetInfo;

create_db!(
  CoordinatorSubstrateEphemeral {
    ScanEphemeralBlocksFrom: () -> u64,
  }
);

/// These are all the events which generate canonical messages
pub struct EphemeralEvents {
  block_hash: BlockHash,
  time: u64,
  events: Events,
}

/// The event stream for ephemeral events.
pub struct EphemeralEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
  public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
}

impl<D: Db> EphemeralEventStream<D> {
  /// Create a new ephemeral event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(
    db: D,
    serai: Arc<Serai>,
    public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
  ) -> Self {
    Self { db, serai, public_serai_auxiliary_key }
  }

  fn new_tributary_validator_set_info(
    txn: &mut impl DbTxn,
    public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
    networks_validators: &[(SeraiAddress, u16)],
    set: ExternalValidatorSet,
    block: &EphemeralEvents,
  ) {
    let mut are_we_in_this_networks_set = false;
    let mut tributary_validators: Vec<TributaryValidator> =
      Vec::with_capacity(networks_validators.len());

    // Fetch all of the validators' auxiliary keys, using the NetworkId::Serai and the
    // NetworkId::External(..) auxiliary keys, both already indexed by the cosign protocol, and
    // create the new TributaryValidatorSet struct
    for (identity, weight) in networks_validators {
      let external_networks_auxiliary_keys =
        match serai_cosign::AuxiliaryKeys::get(txn, set.network.into(), *identity)
          .expect("selected validator lacked auxiliary keys")
        {
          AuxiliaryKeysStruct::Serai(_) => {
            // We skipped non ExternalValidatorSet set_decided events
            // before the function run
            unreachable!("We only coordinate over external networks")
          }
          AuxiliaryKeysStruct::Bitcoin(substrate, external) |
          AuxiliaryKeysStruct::Ethereum(substrate, external) => (substrate, external.to_vec()),
          AuxiliaryKeysStruct::Monero(substrate) => (substrate, substrate.to_vec()),
        };

      let validators_serai_auxiliary_pubkey =
        serai_cosign::serai_networks_auxiliary_key(txn, *identity).0;

      // Now our coordinator's `SERAI_KEY` env var must correspond to
      // the latest Serai auxiliary key published by us
      if validators_serai_auxiliary_pubkey == public_serai_auxiliary_key {
        are_we_in_this_networks_set = true;
      }

      tributary_validators.push(TributaryValidator {
        serai_networks_auxiliary_key: validators_serai_auxiliary_pubkey.to_bytes(),
        networks_substrate_key: external_networks_auxiliary_keys.0,
        networks_external_key: external_networks_auxiliary_keys.1,
        weight: *weight,
      });
    }

    if are_we_in_this_networks_set {
      // Do the summation in u32 so we don't risk a u16 overflow
      let total_network_weight =
        networks_validators.iter().map(|(_, weight)| u32::from(*weight)).sum::<u32>();
      assert!(
        total_network_weight <= u32::from(KeyShares::MAX_PER_SET),
        "{set:?} has {total_network_weight} key shares when the max is {}",
        KeyShares::MAX_PER_SET
      );

      let tributary_validator_set = TributaryValidatorSet::new(tributary_validators);
      let tributary_validator_set_info = TributaryValidatorSetInfo {
        set,
        serai_block: block.block_hash.0,
        declaration_time: block.time,
        tributary_validator_set,
      };
      // These aren't serialized, and we immediately serialize and drop this, so this isn't
      // necessary. It's just good practice not have this be dirty
      crate::EphemeralNewDecidedSet::send(txn, &tributary_validator_set_info);
    }
  }
}

impl<D: Db> ContinuallyRan for EphemeralEventStream<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let Some(latest_cosigned_block_number) =
        Cosigning::<D>::latest_cosigned_block_number(&self.db)
          // Errors if Faulted session exists and keeps re-trying this task
          // protocol will be halted not able to progress
          .map_err(|e| format!("Error getting latest cosigned block number: {e:?}"))?
      else {
        return Ok(false);
      };

      let start_scan_block_number = ScanEphemeralBlocksFrom::get(&self.db).unwrap_or(0);
      self.process_range(start_scan_block_number, latest_cosigned_block_number).await
    }
  }
}

impl<D: Db> FuturesRangeProcessor for EphemeralEventStream<D> {
  type Item = EphemeralEvents;
  // Sync the next set of upcoming blocks all at once to minimize latency
  const ITEMS_TO_PROCESS_AT_ONCE: u64 = 50;

  // For a cosigned block, fetch all relevant events
  fn fetch_item(
    &self,
    block_number: u64,
  ) -> impl Send + 'static + Future<Output = Result<(u64, Self::Item), Self::Error>> {
    let db = self.db.clone();
    let serai = self.serai.clone();
    async move {
      let block_hash = Cosigning::<D>::get_cosigned_blocks_hash(&db, block_number);
      let block_hash = match block_hash {
        Ok(Some(block_hash)) => block_hash,
        Ok(None) => {
          panic!(
            "iterating to latest cosigned block but couldn't get \
             cosigned block number {block_number}"
          )
        }
        Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_owned()),
      };

      let serai_block = serai
        .block(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block #{block_hash}: {e}"))?
        .unwrap_or_else(|| {
          // If latest_cosigned_block_number returned this block number
          // as cosigned and we iterated to it then it must exist on serai
          panic!(
            "Serai node didn't have block #{block_number} which should've been finalized and \
             cosigned"
          )
        });

      let events = serai
        .events(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block events #{block_hash}: {e}"))?;

      // We use time in seconds, not milliseconds, here
      let time = serai_block.header.unix_time_in_millis() / 1000;
      Ok((block_number, EphemeralEvents { block_hash, time, events }))
    }
  }

  fn process_item(&mut self, block_number: u64, block: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();

    let validator_sets_events = block.events.validator_sets();

    // First, handle new decided set events in the block. Sends message for
    // own self processor acknowledgement of set inclusion and DKG participation
    for set_decided in validator_sets_events.set_decided_events() {
      let serai_client_serai::abi::validator_sets::Event::SetDecided { set, validators } =
        set_decided
      else {
        unreachable!("`SetDecided` event wasn't a `SetDecided` event: {set_decided:?}");
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

      assert!(
        u16::try_from(validators.len()).is_ok(),
        "more than u16::MAX validators sent by Serai"
      );

      let networks_validators = validators
        .iter()
        .map(|(validator, weight)| (*validator, u16::from(*weight)))
        .collect::<Vec<_>>();

      Self::new_tributary_validator_set_info(
        &mut txn,
        self.public_serai_auxiliary_key,
        &networks_validators,
        set,
        &block,
      );
    }

    // Second, handle accepted handover events in the block,
    // sends message for own self processor acknowledgement of the need to publish slash reports.
    for accepted_handover in validator_sets_events.accepted_handover_events() {
      let serai_client_serai::abi::validator_sets::Event::AcceptedHandover { set } =
        accepted_handover
      else {
        unreachable!(
          "AcceptedHandover event wasn't a AcceptedHandover event: {accepted_handover:?}"
        );
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

      crate::EphemeralSetHasToSignSlashReport::send(&mut txn, set);
    }

    ScanEphemeralBlocksFrom::set(&mut txn, &(block_number + 1));
    txn.commit();
    Ok(())
  }
}
