use core::time::Duration;
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use tokio::{
  sync::{mpsc, Mutex, RwLock},
  time::sleep,
};

use borsh::BorshSerialize;
use sp_application_crypto::RuntimePublic;
use serai_client::{
  primitives::{ExternalNetworkId, Signature, EXTERNAL_NETWORKS},
  validator_sets::primitives::{ExternalValidatorSet, Session},
  Serai, SeraiError, TemporalSerai,
};

use serai_db::{Get, DbTxn, Db, create_db};

use processor_messages::coordinator::cosign_block_msg;

use crate::{
  p2p::{CosignedBlock, GossipMessageKind, P2p},
  substrate::LatestCosignedBlock,
};

create_db! {
  CosignDb {
    ReceivedCosign: (set: ExternalValidatorSet, block: [u8; 32]) -> CosignedBlock,
    LatestCosign: (network: ExternalNetworkId) -> CosignedBlock,
    DistinctChain: (set: ExternalValidatorSet) -> (),
  }
}

pub struct CosignEvaluator<D: Db> {
  db: Mutex<D>,
  serai: Arc<Serai>,
  stakes: RwLock<Option<HashMap<ExternalNetworkId, u64>>>,
  latest_cosigns: RwLock<HashMap<ExternalNetworkId, CosignedBlock>>,
}

impl<D: Db> CosignEvaluator<D> {
  async fn update_latest_cosign(&self) {
    let stakes_lock = self.stakes.read().await;
    // If we haven't gotten the stake data yet, return
    let Some(stakes) = stakes_lock.as_ref() else { return };

    let total_stake = stakes.values().copied().sum::<u64>();

    let latest_cosigns = self.latest_cosigns.read().await;
    let mut highest_block = 0;
    for cosign in latest_cosigns.values() {
      let mut networks = HashSet::new();
      for (network, sub_cosign) in &*latest_cosigns {
        if sub_cosign.block_number >= cosign.block_number {
          networks.insert(network);
        }
      }
      let sum_stake =
        networks.into_iter().map(|network| stakes.get(network).unwrap_or(&0)).sum::<u64>();
      let needed_stake = ((total_stake * 2) / 3) + 1;
      if (total_stake == 0) || (sum_stake > needed_stake) {
        highest_block = highest_block.max(cosign.block_number);
      }
    }

    let mut db_lock = self.db.lock().await;
    let mut txn = db_lock.txn();
    if highest_block > LatestCosignedBlock::latest_cosigned_block(&txn) {
      log::info!("setting latest cosigned block to {}", highest_block);
      LatestCosignedBlock::set(&mut txn, &highest_block);
    }
    txn.commit();
  }

  async fn update_stakes(&self) -> Result<(), SeraiError> {
    let serai = self.serai.as_of_latest_finalized_block().await?;

    let mut stakes = HashMap::new();
    for network in EXTERNAL_NETWORKS {
      // Use if this network has published a Batch for a short-circuit of if they've ever set a key
      let set_key = serai.in_instructions().last_batch_for_network(network).await?.is_some();
      if set_key {
        stakes.insert(
          network,
          serai
            .validator_sets()
            .total_allocated_stake(network.into())
            .await?
            .expect("network which published a batch didn't have a stake set")
            .0,
        );
      }
    }

    // Since we've successfully built stakes, set it
    *self.stakes.write().await = Some(stakes);

    self.update_latest_cosign().await;

    Ok(())
  }

  // Uses Err to signify a message should be retried
  async fn handle_new_cosign(&self, cosign: CosignedBlock) -> Result<(), SeraiError> {
    // If we already have this cosign or a newer cosign, return
    if let Some(latest) = self.latest_cosigns.read().await.get(&cosign.network) {
      if latest.block_number >= cosign.block_number {
        return Ok(());
      }
    }

    // If this an old cosign (older than a day), drop it
    let latest_block = self.serai.latest_finalized_block().await?;
    if (cosign.block_number + (24 * 60 * 60 / 6)) < latest_block.number() {
      log::debug!("received old cosign supposedly signed by {:?}", cosign.network);
      return Ok(());
    }

    let Some(block) = self.serai.finalized_block_by_number(cosign.block_number).await? else {
      log::warn!("received cosign with a block number which doesn't map to a block");
      return Ok(());
    };

    async fn set_with_keys_fn(
      serai: &TemporalSerai<'_>,
      network: ExternalNetworkId,
    ) -> Result<Option<ExternalValidatorSet>, SeraiError> {
      let Some(latest_session) = serai.validator_sets().session(network.into()).await? else {
        log::warn!("received cosign from {:?}, which doesn't yet have a session", network);
        return Ok(None);
      };
      let prior_session = Session(latest_session.0.saturating_sub(1));
      Ok(Some(
        if serai
          .validator_sets()
          .keys(ExternalValidatorSet { network, session: prior_session })
          .await?
          .is_some()
        {
          ExternalValidatorSet { network, session: prior_session }
        } else {
          ExternalValidatorSet { network, session: latest_session }
        },
      ))
    }

    // Get the key for this network as of the prior block
    // If we have two chains, this value may be different across chains depending on if one chain
    // included the set_keys and one didn't
    // Because set_keys will force a cosign, it will force detection of distinct blocks
    // re: set_keys using keys prior to set_keys (assumed amenable to all)
    let serai = self.serai.as_of(block.header.parent_hash.into());

    let Some(set_with_keys) = set_with_keys_fn(&serai, cosign.network).await? else {
      return Ok(());
    };
    let Some(keys) = serai.validator_sets().keys(set_with_keys).await? else {
      log::warn!("received cosign for a block we didn't have keys for");
      return Ok(());
    };

    if !keys
      .0
      .verify(&cosign_block_msg(cosign.block_number, cosign.block), &Signature(cosign.signature))
    {
      log::warn!("received cosigned block with an invalid signature");
      return Ok(());
    }

    log::info!(
      "received cosign for block {} ({}) by {:?}",
      block.number(),
      hex::encode(cosign.block),
      cosign.network
    );

    // Save this cosign to the DB
    {
      let mut db = self.db.lock().await;
      let mut txn = db.txn();
      ReceivedCosign::set(&mut txn, set_with_keys, cosign.block, &cosign);
      LatestCosign::set(&mut txn, set_with_keys.network, &(cosign));
      txn.commit();
    }

    if cosign.block != block.hash() {
      log::error!(
        "received cosign for a distinct block at {}. we have {}. cosign had {}",
        cosign.block_number,
        hex::encode(block.hash()),
        hex::encode(cosign.block)
      );

      let serai = self.serai.as_of(latest_block.hash());

      let mut db = self.db.lock().await;
      // Save this set as being on a different chain
      let mut txn = db.txn();
      DistinctChain::set(&mut txn, set_with_keys, &());
      txn.commit();

      let mut total_stake = 0;
      let mut total_on_distinct_chain = 0;
      for network in EXTERNAL_NETWORKS {
        // Get the current set for this network
        let set_with_keys = {
          let mut res;
          while {
            res = set_with_keys_fn(&serai, network).await;
            res.is_err()
          } {
            log::error!(
              "couldn't get the set with keys when checking for a distinct chain: {:?}",
              res
            );
            tokio::time::sleep(core::time::Duration::from_secs(3)).await;
          }
          res.unwrap()
        };

        // Get its stake
        // Doesn't use the stakes inside self to prevent deadlocks re: multi-lock acquisition
        if let Some(set_with_keys) = set_with_keys {
          let stake = {
            let mut res;
            while {
              res =
                serai.validator_sets().total_allocated_stake(set_with_keys.network.into()).await;
              res.is_err()
            } {
              log::error!(
                "couldn't get total allocated stake when checking for a distinct chain: {:?}",
                res
              );
              tokio::time::sleep(core::time::Duration::from_secs(3)).await;
            }
            res.unwrap()
          };

          if let Some(stake) = stake {
            total_stake += stake.0;

            if DistinctChain::get(&*db, set_with_keys).is_some() {
              total_on_distinct_chain += stake.0;
            }
          }
        }
      }

      // See https://github.com/serai-dex/serai/issues/339 for the reasoning on 17%
      if (total_stake * 17 / 100) <= total_on_distinct_chain {
        panic!("17% of validator sets (by stake) have co-signed a distinct chain");
      }
    } else {
      {
        let mut latest_cosigns = self.latest_cosigns.write().await;
        latest_cosigns.insert(cosign.network, cosign);
      }
      self.update_latest_cosign().await;
    }

    Ok(())
  }

  #[allow(clippy::new_ret_no_self)]
  pub fn new<P: P2p>(db: D, p2p: P, serai: Arc<Serai>) -> mpsc::UnboundedSender<CosignedBlock> {
    let mut latest_cosigns = HashMap::new();
    for network in EXTERNAL_NETWORKS {
      if let Some(cosign) = LatestCosign::get(&db, network) {
        latest_cosigns.insert(network, cosign);
      }
    }

    let evaluator = Arc::new(Self {
      db: Mutex::new(db),
      serai,
      stakes: RwLock::new(None),
      latest_cosigns: RwLock::new(latest_cosigns),
    });

    // Spawn a task to update stakes regularly
    tokio::spawn({
      let evaluator = evaluator.clone();
      async move {
        loop {
          // Run this until it passes
          while evaluator.update_stakes().await.is_err() {
            log::warn!("couldn't update stakes in the cosign evaluator");
            // Try again in 10 seconds
            sleep(Duration::from_secs(10)).await;
          }
          // Run it every 10 minutes as we don't need the exact stake data for this to be valid
          sleep(Duration::from_secs(10 * 60)).await;
        }
      }
    });

    // Spawn a task to receive cosigns and handle them
    let (send, mut recv) = mpsc::unbounded_channel();
    tokio::spawn({
      let evaluator = evaluator.clone();
      async move {
        while let Some(msg) = recv.recv().await {
          while evaluator.handle_new_cosign(msg).await.is_err() {
            // Try again in 10 seconds
            sleep(Duration::from_secs(10)).await;
          }
        }
      }
    });

    // Spawn a task to rebroadcast the most recent cosigns
    tokio::spawn({
      async move {
        loop {
          let cosigns = evaluator.latest_cosigns.read().await.values().copied().collect::<Vec<_>>();
          for cosign in cosigns {
            let mut buf = vec![];
            cosign.serialize(&mut buf).unwrap();
            P2p::broadcast(&p2p, GossipMessageKind::CosignedBlock, buf).await;
          }
          sleep(Duration::from_secs(60)).await;
        }
      }
    });

    // Return the channel to send cosigns
    send
  }
}
