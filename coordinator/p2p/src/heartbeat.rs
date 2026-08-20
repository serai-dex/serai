use core::future::Future;
use std::time::{Duration, Instant};

use serai_primitives::validator_sets::{ExternalValidatorSet, KeyShares};

use futures_lite::FutureExt as _;

use tributary_sdk::{ReadWrite as _, TransactionTrait, Block, Tributary, TributaryReader};

use serai_db::Db;
use serai_task::ContinuallyRan;

use crate::{Heartbeat, Peer as _, P2p};

// Amount of blocks in a minute
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
const BLOCKS_PER_MINUTE: usize = {
  let minute = Duration::from_mins(1).as_millis();
  let result = minute.div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME.as_millis()) as usize;
  // Ensure this can be round-tripped and no truncation actually occurred
  assert!(
    tributary_sdk::tendermint::TARGET_BLOCK_TIME.checked_mul(result as u32).unwrap().as_millis() ==
      minute
  );
  result
};

/// The minimum amount of blocks to include/included within a batch, assuming there's blocks to
/// include in the batch.
///
/// This decides the size limit of the Batch (the Block size limit multiplied by the minimum amount
/// of blocks we'll send). The actual amount of blocks sent will be the amount which fits within
/// the size limit.
pub const MIN_BLOCKS_PER_BATCH: usize = BLOCKS_PER_MINUTE + 1;

/// The size limit for a batch of blocks sent in response to a Heartbeat.
///
/// This estimates the size of a commit as `32 + (MAX_VALIDATORS * 128)`. At the time of writing, a
/// commit is `8 + (validators * 32) + (32 + (validators * 32))` (for the time, list of validators,
/// and aggregate signature). Accordingly, this should be a safe over-estimate.
#[expect(clippy::as_conversions)]
pub const BATCH_SIZE_LIMIT: usize = MIN_BLOCKS_PER_BATCH *
  (tributary_sdk::BLOCK_SIZE_LIMIT + 32 + ((KeyShares::MAX_PER_SET as usize) * 128));

/// Sends a heartbeat to other validators on regular intervals informing them of our Tributary's
/// tip.
///
/// If the other validator has more blocks then we do, they're expected to inform us. This forms
/// the sync protocol for our Tributaries.
pub(crate) struct HeartbeatTask<
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: TransactionTrait,
  P: P2p,
> {
  set: ExternalValidatorSet,
  tributary: Tributary<TD, Tx, P>,
  reader: TributaryReader<TD, Tx>,
  p2p: P,
  last_observed_block: [u8; 32],
  time_of_last_observed_block: Option<Instant>,
}

impl<TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, Tx: TransactionTrait, P: P2p>
  HeartbeatTask<TD, Tx, P>
{
  pub(crate) fn new(
    set: ExternalValidatorSet,
    tributary: Tributary<TD, Tx, P>,
    reader: TributaryReader<TD, Tx>,
    p2p: P,
  ) -> Self {
    let tip = reader.tip();
    Self {
      set,
      tributary,
      reader,
      p2p,
      last_observed_block: tip,
      time_of_last_observed_block: None,
    }
  }
}

impl<TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, Tx: TransactionTrait, P: P2p>
  ContinuallyRan for HeartbeatTask<TD, Tx, P>
{
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut tip = self.reader.tip();
      let mut tip_is_stale = false;
      if tip != self.last_observed_block {
        self.last_observed_block = tip;
        self.time_of_last_observed_block = Some(Instant::now());
      }

      // If our blockchain hasn't had a block in the past minute, trigger the heartbeat protocol
      const TIME_TO_TRIGGER_SYNCING: Duration = Duration::from_mins(1);
      let mut synced_block = false;
      if self.time_of_last_observed_block.is_none_or(|time_of_last_observed_block| {
        time_of_last_observed_block.elapsed() >= TIME_TO_TRIGGER_SYNCING
      }) {
        // This requests all peers for this network, without differentiating by session
        // This should be fine as most validators should overlap across sessions
        'peer: for peer in self.p2p.peers(self.set.network).await {
          loop {
            // Create the request for blocks
            if tip_is_stale {
              tip = self.reader.tip();
              tip_is_stale = false;
            }
            // Necessary due to https://github.com/rust-lang/rust/issues/100013
            let Some(blocks) = peer
              .send_heartbeat(Heartbeat { set: self.set, latest_block_hash: tip })
              .boxed()
              .await
            else {
              continue 'peer;
            };

            // This is the final batch if it has less than the maximum amount of blocks
            // (signifying there weren't more blocks after this to fill the batch with)
            let final_batch = blocks.len() < MIN_BLOCKS_PER_BATCH;

            // Sync each block
            for block_with_commit in blocks {
              let Ok(block) = Block::read(&mut block_with_commit.block.as_slice()) else {
                // TODO: Disconnect/slash this peer
                log::warn!("received invalid Block inside response to heartbeat");
                continue 'peer;
              };

              // Attempt to sync the block
              if !self.tributary.sync_block(block, block_with_commit.commit).await {
                // The block may be invalid or stale if we added a block elsewhere
                if (!tip_is_stale) && (tip != self.reader.tip()) {
                  // Since the Tributary's tip advanced on its own, return
                  return Ok(false);
                }

                // Since this block was invalid or stale in a way non-trivial to detect, try to
                // sync with the next peer
                continue 'peer;
              }

              // Because we synced a block, flag the tip as stale
              tip_is_stale = true;
              // And that we did sync a block
              synced_block = true;
            }

            // If this was the final batch, move on from this peer
            // We could assume they were honest and we are done syncing the chain, but this is a
            // bit more robust
            if final_batch {
              continue 'peer;
            }
          }
        }

        // This will cause the tak to be run less and less often, ensuring we aren't spamming the
        // net if we legitimately aren't making progress
        if !synced_block {
          Err(format!(
            "tried to sync blocks for {:?} since we haven't seen one {} but didn't",
            self.set,
            match self.time_of_last_observed_block {
              None => "since booting".to_owned(),
              Some(time_of_last_observed_block) =>
                format!("in {} seconds", time_of_last_observed_block.elapsed().as_secs()),
            }
          ))?;
        }
      }

      Ok(synced_block)
    }
  }
}
