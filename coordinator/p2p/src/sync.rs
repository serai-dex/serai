use core::sync::atomic::{Ordering, AtomicBool};
use std::time::Instant;

use serai_primitives::validator_sets::ExternalValidatorSet;

use tributary_sdk::{ReadWriteAsBorsh, AggregateSignature, Transaction, Block, TributaryHandle};

use serai_db::Db;
use serai_task::ContinuallyRan;

use futures_util::StreamExt as _;

use crate::{CommittedTributaryBlock, SyncRequest, Peer, P2p};

async fn sync_from_peer<
  'p2p,
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: 'static + Send + Sync + Transaction,
  P: tendermint::Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<Tx>>>,
>(
  set: ExternalValidatorSet,
  tributary: &TributaryHandle<TD, Tx>,
  synced_block: &AtomicBool,
  peer: impl Peer<'p2p, Tx>,
) -> bool {
  // Sync until we're caught up
  while tributary.blocks_behind().await != 0 {
    let mut latest_block_hash = tributary.tip().unwrap_or(tributary.genesis());

    let Ok(Some(blocks)) = tokio::time::timeout(
      {
        let sync_batch_size_u32 = u32::try_from(super::SYNC_BATCH_SIZE).unwrap_or(u32::MAX);
        P::LATENCY_TIME
          .saturating_mul(2)
          .saturating_add(P::BLOCK_DOWNLOADING_TIME.saturating_mul(sync_batch_size_u32))
      },
      peer.send_sync_request(SyncRequest { set, latest_block_hash }),
    )
    .await
    else {
      break;
    };

    if blocks.is_empty() {
      return false;
    }

    for CommittedTributaryBlock { block: ReadWriteAsBorsh(block), commit } in blocks {
      if block.parent() != latest_block_hash {
        // TODO: Disconnect peer
        return false;
      }
      latest_block_hash = block.hash();

      let next_block_notification = tributary.next_block_notification();
      match tributary.sync(block, commit).await {
        Ok(()) => {}
        Err(
          tributary_sdk::SyncError::InvalidBlock(_) | tributary_sdk::SyncError::InvalidCommit,
        ) => {
          // TODO: Disconnect this peer
          return false;
        }
      }
      /*
        This block has valid syntax, meaning it either:
        - is valid
        - has invalid semantics
        - isn't ephemerally valid

        However, since this block has a valid commit, it SHOULD have valid semantics
        and be ephemerally valid (barring a dishonest supermajority, in which case, we
        SHOULD stall). The exception would be is if it's ephemerally invalid due to another task
        adding the block, hence why we acquired the notification _before_ we called `sync` and now
        await it only if this block hasn't appeared on-chain yet.

        This allows us to safely wait till the next block's notification without any
        timeout or similar.
      */
      if tributary.block(latest_block_hash).is_none() {
        next_block_notification.await;
      }

      /*
        This may be a false positive if we didn't sync a block, but if another task(/peer)
        did or if the Tributary achieved consensus itself.
      */
      synced_block.store(true, Ordering::Release);
    }
  }

  true
}

/// Sync Tributary blocks from other validators.
pub(crate) struct SyncTask<
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: 'static + Send + Sync + Transaction,
  P: P2p<Tx>,
> {
  /// The validator set whose Tributary this is syncing blocks for.
  set: ExternalValidatorSet,
  /// A handle to the Tributary.
  tributary: TributaryHandle<TD, Tx>,
  /// A handle to the peer-to-peer network.
  p2p: P,

  /// The time since which we've been behind by one block.
  behind_by_one: Option<Instant>,
}

impl<
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: 'static + Send + Sync + Transaction,
  P: P2p<Tx>,
> SyncTask<TD, Tx, P>
{
  pub(crate) fn new(set: ExternalValidatorSet, tributary: TributaryHandle<TD, Tx>, p2p: P) -> Self {
    Self { set, tributary, p2p, behind_by_one: None }
  }
}

impl<
  TD: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  Tx: Send + Sync + Transaction,
  P: P2p<Tx>,
> ContinuallyRan for SyncTask<TD, Tx, P>
{
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      {
        let blocks_behind = self.tributary.blocks_behind().await;
        // If we're not behind, we return having made no progress (as there's none to make)
        if blocks_behind == 0 {
          self.behind_by_one = None;
          return Ok(false);
        }
        // If we're only one block behind, only start syncing if it's been the latency time
        if blocks_behind == 1 {
          match self.behind_by_one {
            Some(start) => {
              if Instant::now().duration_since(start) < P::LATENCY_TIME {
                return Ok(false);
              }
            }
            None => {
              // Note we're behind by one block but do not immediately begin syncing
              self.behind_by_one = Some(Instant::now());
              return Ok(false);
            }
          }
        }
      }

      // Clear this counter
      self.behind_by_one = None;
      // Track if we've synced a block
      let synced_block = AtomicBool::new(false);

      let peers = {
        /*
          This requests all peers for this network, without differentiating by session. This
          _should_ be fine as most validators should overlap across sessions, but should be
          improved.

          TODO
        */
        let mut peers = self.p2p.peers(self.set.network).await;

        // Sample a square-root amount of peers
        let peers_from = peers.len().isqrt().clamp(3, 8);
        let mut selected_peers = Vec::with_capacity(peers_from);
        for _ in 0 .. peers_from {
          #[expect(clippy::as_conversions)]
          let Some(i) = (getrandom::u32().unwrap() as usize).checked_rem(peers.len()) else {
            break;
          };
          selected_peers.push(peers.swap_remove(i));
        }
        selected_peers
      };

      /*
        We simultaneously send sync requests to all of these peers to avoid the risk of stalling
        due to trying to sync from a slow peer. This causes us to sync at the rate of the fastest
        randomly selected peer, though it is an unintelligent design which could have its
        inefficiencies optimized out.

        TODO: https://github.com/serai-dex/serai/issues/646
      */
      let mut sync = futures_util::stream::FuturesUnordered::new();
      for peer in peers {
        sync.push(sync_from_peer::<_, _, P>(self.set, &self.tributary, &synced_block, peer));
      }
      while let Some(success) = sync.next().await {
        // If we caught up from any peer, drop all outstanding sync requests
        if success {
          break;
        }
      }
      let synced_block = synced_block.load(Ordering::Acquire);

      // This will cause the tak to be run less and less often, ensuring we aren't spamming the
      // net if we legitimately aren't making progress
      if !synced_block {
        Err(format!(
          "tried to sync blocks for {:?} since we're {} blocks behind but couldn't",
          self.set,
          self.tributary.blocks_behind().await,
        ))?;
      }

      Ok(synced_block)
    }
  }
}
