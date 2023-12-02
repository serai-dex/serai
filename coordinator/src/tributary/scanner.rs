use core::{future::Future, time::Duration};
use std::sync::Arc;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use tokio::sync::broadcast;

use scale::{Encode, Decode};
use serai_client::{validator_sets::primitives::ValidatorSet, Serai};

use serai_db::DbTxn;

use tributary::{
  TransactionKind, Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
};

use crate::{
  Db,
  tributary::handle::{fatal_slash, handle_application_tx},
  processors::Processors,
  tributary::{TributarySpec, Transaction, LastBlock, EventDb},
  P2p,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum RecognizedIdType {
  Batch,
  Plan,
}

pub(crate) trait RIDTrait<FRid>:
  Clone + Fn(ValidatorSet, [u8; 32], RecognizedIdType, Vec<u8>) -> FRid
{
}
impl<FRid, F: Clone + Fn(ValidatorSet, [u8; 32], RecognizedIdType, Vec<u8>) -> FRid> RIDTrait<FRid>
  for F
{
}

// Handle a specific Tributary block
async fn handle_block<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Vec<u8>) -> FPst,
  FRid: Future<Output = ()>,
  RID: RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut D,
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
    if EventDb::get(db, hash, event_id).is_some() {
      event_id += 1;
      continue;
    }

    let mut txn = db.txn();

    match tx {
      TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
        // Since the evidence is on the chain, it should already have been validated
        // We can just punish the signer
        let data = match ev {
          Evidence::ConflictingMessages(first, second) => (first, Some(second)),
          Evidence::ConflictingPrecommit(first, second) => (first, Some(second)),
          Evidence::InvalidPrecommit(first) => (first, None),
          Evidence::InvalidValidRound(first) => (first, None),
        };
        let msgs = (
          decode_signed_message::<TendermintNetwork<D, Transaction, P>>(&data.0).unwrap(),
          if data.1.is_some() {
            Some(
              decode_signed_message::<TendermintNetwork<D, Transaction, P>>(&data.1.unwrap())
                .unwrap(),
            )
          } else {
            None
          },
        );

        // Since anything with evidence is fundamentally faulty behavior, not just temporal errors,
        // mark the node as fatally slashed
        fatal_slash::<D>(
          &mut txn,
          genesis,
          msgs.0.msg.sender,
          &format!("invalid tendermint messages: {:?}", msgs),
        );
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

    EventDb::handle_event(&mut txn, hash, event_id);
    txn.commit();

    event_id += 1;
  }

  // TODO: Trigger any necessary re-attempts
}

pub(crate) async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Vec<u8>) -> FPst,
  FRid: Future<Output = ()>,
  RID: RIDTrait<FRid>,
  P: P2p,
>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  processors: &Pro,
  publish_serai_tx: PST,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = LastBlock::get(db, genesis).unwrap_or(genesis);
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
    let mut txn = db.txn();
    LastBlock::set(&mut txn, genesis, &next);
    txn.commit();
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
  mut tributary_event: broadcast::Receiver<crate::TributaryEvent<D, P>>,
) {
  log::info!("scanning tributaries");

  loop {
    match tributary_event.recv().await {
      Ok(crate::TributaryEvent::NewTributary(crate::ActiveTributary { spec, tributary })) => {
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
            let mut tributary_db = raw_db.clone();
            loop {
              // Check if the set was retired, and if so, don't further operate
              if crate::MainDb::<D>::is_tributary_retired(&raw_db, spec.set()) {
                break;
              }

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
                          if let Ok(serai) = serai.as_of_latest_finalized_block().await {
                            let serai = serai.validator_sets();
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

              // Run either when the notification fires, or every interval of block_time
              let _ = tokio::time::timeout(
                Duration::from_secs(tributary::Tributary::<D, Transaction, P>::block_time().into()),
                next_block_notification,
              )
              .await;
            }
          }
        });
      }
      // The above loop simply checks the DB every few seconds, voiding the need for this event
      Ok(crate::TributaryEvent::TributaryRetired(_)) => {}
      Err(broadcast::error::RecvError::Lagged(_)) => {
        panic!("scan_tributaries lagged to handle tributary_event")
      }
      Err(broadcast::error::RecvError::Closed) => panic!("tributary_event sender closed"),
    }
  }
}
