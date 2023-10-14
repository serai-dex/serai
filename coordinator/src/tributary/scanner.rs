use core::future::Future;
use std::sync::Arc;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use tokio::sync::broadcast;

use serai_client::{
  primitives::NetworkId, validator_sets::primitives::ValidatorSet, subxt::utils::Encoded, Serai,
};

use tributary::{
  TransactionKind, Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, decode_evidence},
    TendermintNetwork,
  },
};

use serai_db::DbTxn;

use crate::{
  Db,
  tributary::handle::handle_application_tx,
  processors::Processors,
  tributary::{TributaryDb, TributarySpec, Transaction},
  P2p,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecognizedIdType {
  Batch,
  Plan,
}

pub(crate) trait RIDTrait<FRid>:
  Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32], u32) -> FRid
{
}
impl<FRid, F: Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32], u32) -> FRid>
  RIDTrait<FRid> for F
{
}

// Handle a specific Tributary block
#[allow(clippy::needless_pass_by_ref_mut)] // False positive?
async fn handle_block<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = ()>,
  RID: RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  block: Block<Transaction>,
) {
  log::info!("found block for Tributary {:?}", spec.set());

  let genesis = spec.genesis();
  let hash = block.hash();

  let mut event_id = 0;
  #[allow(clippy::explicit_counter_loop)] // event_id isn't TX index. It just currently lines up
  for tx in block.transactions {
    if TributaryDb::<D>::handled_event(&db.0, hash, event_id) {
      event_id += 1;
      continue;
    }

    let mut txn = db.0.txn();

    match tx {
      TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
        // Since the evidence is on the chain, it should already have been validated
        // We can just punish the signer
        let msgs = decode_evidence::<TendermintNetwork<D, Transaction, P>>(&ev).unwrap();

        // Since anything with evidence is fundamentally faulty behavior, not just temporal errors,
        // mark the node as fatally slashed
        TributaryDb::<D>::set_fatally_slashed(&mut txn, genesis, msgs.0.msg.sender);

        // TODO2: disconnect the node from network/ban from further participation in Tributary
      }
      TributaryTransaction::Application(tx) => {
        handle_application_tx::<D, _, _, _, _, _>(
          tx,
          spec,
          processors,
          publish_serai_tx.clone(),
          key,
          recognized_id.clone(),
          &mut txn,
        )
        .await;
      }
    }

    TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
    txn.commit();

    event_id += 1;
  }

  // TODO: Trigger any necessary re-attempts
}

pub(crate) async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = ()>,
  RID: RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = db.last_block(genesis);
  while let Some(next) = tributary.block_after(&last_block) {
    let block = tributary.block(&next).unwrap();

    // Make sure we have all of the provided transactions for this block
    for tx in &block.transactions {
      // Provided TXs will appear first in the Block, so we can break after we hit a non-Provided
      let TransactionKind::Provided(order) = tx.kind() else {
        break;
      };

      // make sure we have all the provided txs in this block locally
      if !tributary.locally_provided_txs_in_block(&block.hash(), order) {
        return;
      }
    }

    handle_block::<_, _, _, _, _, _, P>(
      db,
      key,
      recognized_id.clone(),
      processors,
      publish_serai_tx.clone(),
      spec,
      block,
    )
    .await;
    last_block = next;
    db.set_last_block(genesis, next);
  }
}

pub(crate) async fn scan_tributaries_task<
  D: Db,
  Pro: Processors,
  P: P2p,
  FRid: Send + Future<Output = ()>,
  RID: 'static + Send + Sync + RIDTrait<FRid>,
>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: Pro,
  serai: Arc<Serai>,
  mut new_tributary: broadcast::Receiver<crate::ActiveTributary<D, P>>,
) {
  log::info!("scanning tributaries");

  loop {
    match new_tributary.recv().await {
      Ok(crate::ActiveTributary { spec, tributary }) => {
        // For each Tributary, spawn a dedicated scanner task
        tokio::spawn({
          let raw_db = raw_db.clone();
          let key = key.clone();
          let recognized_id = recognized_id.clone();
          let processors = processors.clone();
          let serai = serai.clone();
          async move {
            let spec = &spec;
            let reader = tributary.reader();
            let mut tributary_db = TributaryDb::new(raw_db.clone());
            loop {
              // Obtain the next block notification now to prevent obtaining it immediately after
              // the next block occurs
              let next_block_notification = tributary.next_block_notification().await;

              handle_new_blocks::<_, _, _, _, _, _, P>(
                &mut tributary_db,
                &key,
                recognized_id.clone(),
                &processors,
                |set, tx| {
                  let serai = serai.clone();
                  async move {
                    loop {
                      match serai.publish(&tx).await {
                        Ok(_) => {
                          log::info!("set key pair for {set:?}");
                          break;
                        }
                        // This is assumed to be some ephemeral error due to the assumed fault-free
                        // creation
                        // TODO2: Differentiate connection errors from invariants
                        Err(e) => {
                          if let Ok(latest) = serai.latest_block_hash().await {
                            let serai = serai.as_of(latest).validator_sets();
                            // Check if this failed because the keys were already set by someone
                            // else
                            if matches!(serai.keys(spec.set()).await, Ok(Some(_))) {
                              log::info!("another coordinator set key pair for {:?}", set);
                              break;
                            }

                            // The above block may return false if the keys have been pruned from
                            // the state
                            // Check if this session is no longer the latest session, meaning it at
                            // some point did set keys, and we're just operating off very
                            // historical data
                            if let Ok(Some(current_session)) =
                              serai.session(spec.set().network).await
                            {
                              if current_session.0 > spec.set().session.0 {
                                log::warn!(
                                  "trying to set keys for a set which isn't the latest {:?}",
                                  set
                                );
                                break;
                              }
                            }
                          }

                          log::error!(
                            "couldn't connect to Serai node to publish set_keys TX: {:?}",
                            e
                          );
                          tokio::time::sleep(core::time::Duration::from_secs(10)).await;
                        }
                      }
                    }
                  }
                },
                spec,
                &reader,
              )
              .await;

              next_block_notification
                .await
                .map_err(|_| "")
                .expect("tributary dropped its notifications?");
            }
          }
        });
      }
      Err(broadcast::error::RecvError::Lagged(_)) => {
        panic!("scan_tributaries lagged to handle new_tributary")
      }
      Err(broadcast::error::RecvError::Closed) => panic!("new_tributary sender closed"),
    }
  }
}
