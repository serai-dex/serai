use core::time::Duration;
use std::{
  sync::{Arc, Mutex, RwLock},
  collections::{HashSet, HashMap},
};

use tokio::{sync::mpsc, time::sleep};

use scale::Encode;
use sp_application_crypto::RuntimePublic;
use serai_client::{
  primitives::{NETWORKS, NetworkId, Signature},
  validator_sets::primitives::{Session, ValidatorSet},
  SeraiError, Serai,
};

use serai_db::{DbTxn, Db};

use processor_messages::coordinator::cosign_block_msg;

use crate::{
  p2p::{CosignedBlock, P2pMessageKind, P2p},
  substrate::SubstrateDb,
};

pub struct CosignEvaluator<D: Db> {
  db: Mutex<D>,
  serai: Arc<Serai>,
  stakes: RwLock<Option<HashMap<NetworkId, u64>>>,
  latest_cosigns: RwLock<HashMap<NetworkId, (u64, CosignedBlock)>>,
}

impl<D: Db> CosignEvaluator<D> {
  fn update_latest_cosign(&self) {
    let stakes_lock = self.stakes.read().unwrap();
    // If we haven't gotten the stake data yet, return
    let Some(stakes) = stakes_lock.as_ref() else { return };

    let latest_cosigns = self.latest_cosigns.read().unwrap();
    let mut highest_block = 0;
    for (block_num, _) in latest_cosigns.values() {
      let mut networks = HashSet::new();
      for (network, (sub_block_num, _)) in &*latest_cosigns {
        if sub_block_num >= block_num {
          networks.insert(network);
        }
      }
      let sum_stake =
        networks.into_iter().map(|network| stakes.get(network).unwrap_or(&0)).sum::<u64>();
      let total_stake = stakes.values().cloned().sum::<u64>();
      let needed_stake = ((total_stake * 2) / 3) + 1;
      if (total_stake == 0) || (sum_stake > needed_stake) {
        highest_block = highest_block.max(*block_num);
      }
    }

    let mut db_lock = self.db.lock().unwrap();
    let mut txn = db_lock.txn();
    if highest_block > SubstrateDb::<D>::latest_cosigned_block(&txn) {
      log::info!("setting latest cosigned block to {}", highest_block);
      SubstrateDb::<D>::set_latest_cosigned_block(&mut txn, highest_block);
    }
    txn.commit();
  }

  async fn update_stakes(&self) -> Result<(), SeraiError> {
    let serai = self.serai.as_of(self.serai.latest_block_hash().await?);

    let mut stakes = HashMap::new();
    for network in NETWORKS {
      // Use if this network has published a Batch for a short-circuit of if they've ever set a key
      let set_key = serai.in_instructions().last_batch_for_network(network).await?.is_some();
      if set_key {
        stakes.insert(
          network,
          serai
            .validator_sets()
            .total_allocated_stake(network)
            .await?
            .expect("network which published a batch didn't have a stake set")
            .0,
        );
      }
    }

    // Since we've successfully built stakes, set it
    *self.stakes.write().unwrap() = Some(stakes);

    self.update_latest_cosign();

    Ok(())
  }

  // Uses Err to signify a message should be retried
  async fn handle_new_cosign(&self, cosign: CosignedBlock) -> Result<(), SeraiError> {
    let Some(block) = self.serai.block(cosign.block).await? else {
      log::warn!("received cosign for an unknown block");
      return Ok(());
    };

    // If this an old cosign, don't bother handling it
    if block.number() <
      self.latest_cosigns.read().unwrap().get(&cosign.network).map(|cosign| cosign.0).unwrap_or(0)
    {
      log::debug!("received old cosign from {:?}", cosign.network);
      return Ok(());
    }

    // Get the key for this network as of the prior block
    let serai = self.serai.as_of(block.header().parent_hash.into());

    let Some(latest_session) = serai.validator_sets().session(cosign.network).await? else {
      log::warn!("received cosign from {:?}, which doesn't yet have a session", cosign.network);
      return Ok(());
    };
    let prior_session = Session(latest_session.0.saturating_sub(1));
    let set_with_keys = if serai
      .validator_sets()
      .keys(ValidatorSet { network: cosign.network, session: prior_session })
      .await?
      .is_some()
    {
      ValidatorSet { network: cosign.network, session: prior_session }
    } else {
      ValidatorSet { network: cosign.network, session: latest_session }
    };

    let Some(keys) = serai.validator_sets().keys(set_with_keys).await? else {
      log::warn!("received cosign for a block we didn't have keys for");
      return Ok(());
    };

    if !keys.0.verify(&cosign_block_msg(cosign.block), &Signature(cosign.signature)) {
      log::warn!("received cosigned block with an invalid signature");
      return Ok(());
    }

    self.latest_cosigns.write().unwrap().insert(cosign.network, (block.number(), cosign));

    self.update_latest_cosign();

    Ok(())
  }

  #[allow(clippy::new_ret_no_self)]
  pub fn new<P: P2p>(db: D, p2p: P, serai: Arc<Serai>) -> mpsc::UnboundedSender<CosignedBlock> {
    let evaluator = Arc::new(Self {
      db: Mutex::new(db),
      serai,
      stakes: RwLock::new(None),
      latest_cosigns: RwLock::new(HashMap::new()),
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
          let cosigns = evaluator
            .latest_cosigns
            .read()
            .unwrap()
            .values()
            .map(|cosign| cosign.1)
            .collect::<Vec<_>>();
          for cosign in cosigns {
            P2p::broadcast(&p2p, P2pMessageKind::CosignedBlock, cosign.encode()).await;
          }
          sleep(Duration::from_secs(60)).await;
        }
      }
    });

    // Return the channel to send cosigns
    send
  }
}
