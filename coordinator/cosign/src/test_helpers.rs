use rand_core::{RngCore, CryptoRng};

use serai_db::DbTxn;

use crate::GlobalCosigningSessionId;
use serai_client_serai::abi::{
  self,
  primitives::{self, BlockHash, network_id::NetworkId},
  Event,
};

/// Seed the DB with the hash for a cosigned Substrate block number.
pub fn set_substrate_block_hash(txn: &mut impl DbTxn, block_number: u64, hash: &BlockHash) {
  crate::SubstrateBlockHash::set(txn, block_number, hash);
}

/// Seed the DB with the latest cosigned block number.
pub fn set_latest_cosigned_block_number(txn: &mut impl DbTxn, block_number: &u64) {
  crate::delay::LatestCosignedBlockNumber::set(txn, block_number);
}

/// Seed the DB to mark a global cosigning session as faulted.
pub fn set_faulted_session(
  txn: &mut impl DbTxn,
  global_cosigning_session: &GlobalCosigningSessionId,
) {
  crate::FaultedCosigningSession::set(txn, global_cosigning_session);
}

/// Delete the hash for a cosigned Substrate block number.
pub fn del_substrate_block_hash(txn: &mut impl DbTxn, block_number: u64) {
  crate::SubstrateBlockHash::del(txn, block_number);
}

/// Delete the latest cosigned block number.
pub fn del_latest_cosigned_block_number(txn: &mut impl DbTxn) {
  crate::delay::LatestCosignedBlockNumber::del(txn);
}

/// Generate a random global cosigning session ID (`[u8; 32]`).
pub fn random_global_cosigning_session_id<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> GlobalCosigningSessionId {
  serai_cosign_types::test_helpers::random_global_cosigning_session_id(rng)
}

/// Delete the latest cosigned block number.
pub fn set_auxiliary_keys(
  txn: &mut impl DbTxn,
  network: NetworkId,
  validator: primitives::address::SeraiAddress,
  keys: &primitives::crypto::EmbeddedEllipticCurveKeys,
) {
  crate::intend::AuxiliaryKeys::set(txn, network, validator, keys);
}

/// Populate the cosigning DB so that `Cosigning::latest_cosigned_block_number` returns
/// the max block number and `Cosigning::cosigned_block(n)` returns the correct hash
/// for each block in the list.
///
/// Also pre-seeds auxiliary keys from `SetEmbeddedEllipticCurveKeys` events found in
/// the provided events, maintaining the protocol invariant that auxiliary keys must exist
/// in the DB before any `SetDecided` event references them.
pub fn seed_cosigned_blocks(
  txn: &mut impl DbTxn,
  block_hashes: &[(u64, BlockHash)],
  events: &[Vec<Event>],
) {
  for &(number, hash) in block_hashes {
    set_substrate_block_hash(txn, number, &hash);
  }
  if let Some(&(max_number, _)) = block_hashes.last() {
    set_latest_cosigned_block_number(txn, &max_number);
  }

  for block_events in events {
    for event in block_events {
      if let Event::ValidatorSets(abi::validator_sets::Event::SetEmbeddedEllipticCurveKeys {
        validator,
        keys,
      }) = event
      {
        set_auxiliary_keys(txn, keys.network(), *validator, keys);
      }
    }
  }
}
