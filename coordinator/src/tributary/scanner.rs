use core::{marker::PhantomData, ops::Deref, future::Future, time::Duration};
use std::sync::Arc;

use rand_core::OsRng;

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use tokio::sync::broadcast;

use scale::{Encode, Decode};
use serai_client::{validator_sets::primitives::ValidatorSet, Serai};

use serai_db::DbTxn;

use processor_messages::coordinator::SubstrateSignableId;

use tributary::{
  TransactionKind, Transaction as TributaryTransaction, TransactionError, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
};

use crate::{
  Db,
  processors::Processors,
  tributary::{*, signing_protocol::*},
  P2p,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum RecognizedIdType {
  Batch,
  Plan,
}

#[async_trait::async_trait]
pub trait RIDTrait {
  async fn recognized_id(
    &self,
    set: ValidatorSet,
    genesis: [u8; 32],
    kind: RecognizedIdType,
    id: Vec<u8>,
  );
}
#[async_trait::async_trait]
impl<
    FRid: Send + Future<Output = ()>,
    F: Sync + Fn(ValidatorSet, [u8; 32], RecognizedIdType, Vec<u8>) -> FRid,
  > RIDTrait for F
{
  async fn recognized_id(
    &self,
    set: ValidatorSet,
    genesis: [u8; 32],
    kind: RecognizedIdType,
    id: Vec<u8>,
  ) {
    (self)(set, genesis, kind, id).await
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PstTxType {
  SetKeys,
  RemoveParticipant([u8; 32]),
}

#[async_trait::async_trait]
pub trait PSTTrait {
  // TODO: Diversify publish_set_keys, publish_remove_participant, then remove PstTxType
  async fn publish_serai_tx(
    &self,
    set: ValidatorSet,
    kind: PstTxType,
    tx: serai_client::Transaction,
  );
}
#[async_trait::async_trait]
impl<
    FPst: Send + Future<Output = ()>,
    F: Sync + Fn(ValidatorSet, PstTxType, serai_client::Transaction) -> FPst,
  > PSTTrait for F
{
  async fn publish_serai_tx(
    &self,
    set: ValidatorSet,
    kind: PstTxType,
    tx: serai_client::Transaction,
  ) {
    (self)(set, kind, tx).await
  }
}

#[async_trait::async_trait]
pub trait PTTTrait {
  async fn publish_tributary_tx(&self, tx: Transaction);
}
#[async_trait::async_trait]
impl<FPtt: Send + Future<Output = ()>, F: Sync + Fn(Transaction) -> FPtt> PTTTrait for F {
  async fn publish_tributary_tx(&self, tx: Transaction) {
    (self)(tx).await
  }
}

pub struct TributaryBlockHandler<
  'a,
  T: DbTxn,
  Pro: Processors,
  PST: PSTTrait,
  PTT: PTTTrait,
  RID: RIDTrait,
  P: P2p,
> {
  pub txn: &'a mut T,
  pub our_key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub recognized_id: &'a RID,
  pub processors: &'a Pro,
  pub publish_serai_tx: &'a PST,
  pub publish_tributary_tx: &'a PTT,
  pub spec: &'a TributarySpec,
  block: Block<Transaction>,
  pub block_number: u32,
  _p2p: PhantomData<P>,
}

impl<T: DbTxn, Pro: Processors, PST: PSTTrait, PTT: PTTTrait, RID: RIDTrait, P: P2p>
  TributaryBlockHandler<'_, T, Pro, PST, PTT, RID, P>
{
  async fn dkg_removal_attempt(&mut self, removing: [u8; 32], attempt: u32) {
    let preprocess =
      (DkgRemoval { spec: self.spec, key: self.our_key, txn: self.txn, removing, attempt })
        .preprocess();
    let mut tx = Transaction::DkgRemoval(SignData {
      plan: removing,
      attempt,
      label: Label::Preprocess,
      data: vec![preprocess.to_vec()],
      signed: Transaction::empty_signed(),
    });
    tx.sign(&mut OsRng, self.spec.genesis(), self.our_key);
    self.publish_tributary_tx.publish_tributary_tx(tx).await;
  }

  pub async fn fatal_slash(&mut self, slashing: [u8; 32], reason: &str) {
    // TODO: If this fatal slash puts the remaining set below the threshold, spin

    let genesis = self.spec.genesis();

    log::warn!("fatally slashing {}. reason: {}", hex::encode(slashing), reason);
    FatallySlashed::set_fatally_slashed(self.txn, genesis, slashing);
    // TODO: disconnect the node from network/ban from further participation in all Tributaries

    // TODO: If during DKG, trigger a re-attempt
    // Despite triggering a re-attempt, this DKG may still complete and may become in-use

    // If during a DKG, remove the participant
    if DkgCompleted::get(self.txn, genesis).is_none() {
      AttemptDb::recognize_topic(self.txn, genesis, Topic::DkgRemoval(slashing));
      self.dkg_removal_attempt(slashing, 0).await;
    }
  }

  // TODO: Once Substrate confirms a key, we need to rotate our validator set OR form a second
  // Tributary post-DKG
  // https://github.com/serai-dex/serai/issues/426

  pub async fn fatal_slash_with_participant_index(&mut self, i: Participant, reason: &str) {
    // Resolve from Participant to <Ristretto as Ciphersuite>::G
    let i = u16::from(i);
    let mut validator = None;
    for (potential, _) in self.spec.validators() {
      let v_i = self.spec.i(potential).unwrap();
      if (u16::from(v_i.start) <= i) && (i < u16::from(v_i.end)) {
        validator = Some(potential);
        break;
      }
    }
    let validator = validator.unwrap();

    self.fatal_slash(validator.to_bytes(), reason).await;
  }

  async fn handle<D: Db>(mut self) {
    log::info!("found block for Tributary {:?}", self.spec.set());

    let transactions = self.block.transactions.clone();
    for tx in transactions {
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

          // Since anything with evidence is fundamentally faulty behavior, not just temporal
          // errors, mark the node as fatally slashed
          self
            .fatal_slash(msgs.0.msg.sender, &format!("invalid tendermint messages: {:?}", msgs))
            .await;
        }
        TributaryTransaction::Application(tx) => {
          self.handle_application_tx(tx).await;
        }
      }
    }

    let genesis = self.spec.genesis();
    for topic in ReattemptDb::take(self.txn, genesis, self.block_number) {
      let attempt = AttemptDb::start_next_attempt(self.txn, genesis, topic);
      /*
        All of these have the same common flow:

        1) Check if this re-attempt is actually needed
        2) If so, dispatch whatever events as needed

        This is because we *always* re-attempt any protocol which had participation. That doesn't
        mean we *should* re-attempt this protocol.

        The alternatives were:
        1) Note on-chain we completed a protocol, halting re-attempts upon 34%.
        2) Vote on-chain to re-attempt a protocol.

        This schema doesn't have any additional messages upon the success case (whereas
        alternative #1 does) and doesn't have overhead (as alternative #2 does, sending votes and
        then preprocesses. This only sends preprocesses).
      */
      match topic {
        Topic::Dkg => {
          if DkgCompleted::get(self.txn, genesis).is_none() {
            // Since it wasn't completed, instruct the processor to start the next attempt
            let id =
              processor_messages::key_gen::KeyGenId { session: self.spec.set().session, attempt };
            let our_i = self.spec.i(Ristretto::generator() * self.our_key.deref()).unwrap();

            // TODO: Handle removed parties (modify n/i to accept list of removed)
            // TODO: Don't try to re-attempt yet spin if too many parties have been removed
            // TODO: Don't fatal slash, yet don't include, parties who have been offline so long as
            // we still meet the needed threshold

            let params =
              frost::ThresholdParams::new(self.spec.t(), self.spec.n(), our_i.start).unwrap();
            let shares = u16::from(our_i.end) - u16::from(our_i.start);

            self
              .processors
              .send(
                self.spec.set().network,
                processor_messages::key_gen::CoordinatorMessage::GenerateKey { id, params, shares },
              )
              .await;
          }
        }
        Topic::DkgConfirmation => {
          panic!("re-attempting DkgConfirmation when we should be re-attempting the Dkg")
        }
        Topic::DkgRemoval(removing) => {
          if DkgCompleted::get(self.txn, genesis).is_none() &&
            LocallyDkgRemoved::get(self.txn, genesis, removing).is_none() &&
            SeraiDkgCompleted::get(self.txn, self.spec.set()).is_none() &&
            SeraiDkgRemoval::get(self.txn, self.spec.set(), removing).is_none()
          {
            // Since it wasn't completed, attempt a new DkgRemoval
            self.dkg_removal_attempt(removing, attempt).await;
          }
        }
        Topic::SubstrateSign(inner_id) => {
          let id = processor_messages::coordinator::SubstrateSignId {
            session: self.spec.set().session,
            id: inner_id,
            attempt,
          };
          match inner_id {
            SubstrateSignableId::CosigningSubstrateBlock(block) => {
              let block_number = SeraiBlockNumber::get(self.txn, block)
                .expect("couldn't get the block number for prior attempted cosign");

              // Check if the cosigner has a signature from our set for this block/a newer one
              let latest_cosign =
                crate::cosign_evaluator::LatestCosign::get(self.txn, self.spec.set().network)
                  .map(|cosign| cosign.block_number)
                  .unwrap_or(0);
              if latest_cosign < block_number {
                // Instruct the processor to start the next attempt
                self
                  .processors
                  .send(
                    self.spec.set().network,
                    processor_messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
                      id,
                      block_number,
                    },
                  )
                  .await;
              }
            }
            SubstrateSignableId::Batch(batch) => {
              // Check if the Batch was published/we're actively publishing it
              todo!();

              // Instruct the processor to start the next attempt
              self
                .processors
                .send(
                  self.spec.set().network,
                  processor_messages::coordinator::CoordinatorMessage::BatchReattempt { id },
                )
                .await;
            }
          }
        }
        Topic::Sign(id) => {
          // Instruct the processor to start the next attempt
          // If it has already noted a completion, it won't send a preprocess and will simply drop
          // the re-attempt message
          self
            .processors
            .send(
              self.spec.set().network,
              processor_messages::sign::CoordinatorMessage::Reattempt {
                id: processor_messages::sign::SignId {
                  session: self.spec.set().session,
                  id,
                  attempt,
                },
              },
            )
            .await;
        }
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  PST: PSTTrait,
  PTT: PTTTrait,
  RID: RIDTrait,
  P: P2p,
>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &RID,
  processors: &Pro,
  publish_serai_tx: &PST,
  publish_tributary_tx: &PTT,
  spec: &TributarySpec,
  tributary: &TributaryReader<D, Transaction>,
) {
  let genesis = tributary.genesis();
  let mut last_block = LastHandledBlock::get(db, genesis).unwrap_or(genesis);
  let mut block_number = TributaryBlockNumber::get(db, last_block).unwrap_or(0);
  while let Some(next) = tributary.block_after(&last_block) {
    let block = tributary.block(&next).unwrap();
    block_number += 1;

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

    let mut txn = db.txn();
    TributaryBlockNumber::set(&mut txn, next, &block_number);
    (TributaryBlockHandler {
      txn: &mut txn,
      spec,
      our_key: key,
      recognized_id,
      processors,
      publish_serai_tx,
      publish_tributary_tx,
      block,
      block_number,
      _p2p: PhantomData::<P>,
    })
    .handle::<D>()
    .await;
    last_block = next;
    LastHandledBlock::set(&mut txn, genesis, &next);
    txn.commit();
  }
}

pub(crate) async fn scan_tributaries_task<
  D: Db,
  Pro: Processors,
  P: P2p,
  RID: 'static + Send + Sync + Clone + RIDTrait,
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
              if crate::db::RetiredTributaryDb::get(&raw_db, spec.set()).is_some() {
                break;
              }

              // Obtain the next block notification now to prevent obtaining it immediately after
              // the next block occurs
              let next_block_notification = tributary.next_block_notification().await;

              handle_new_blocks::<_, _, _, _, _, P>(
                &mut tributary_db,
                &key,
                &recognized_id,
                &processors,
                &|set, tx_type, tx| {
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

                            // The following block is irrelevant, and can/likely will fail, if
                            // we're publishing a TX for an old session
                            // If we're on a newer session, move on
                            if let Ok(Some(current_session)) =
                              serai.session(spec.set().network).await
                            {
                              if current_session.0 > spec.set().session.0 {
                                log::warn!(
                                  "trying to publish a TX relevant to a set {} {:?}",
                                  "which isn't the latest",
                                  set
                                );
                                break;
                              }
                            }

                            // Check if someone else published the TX in question
                            match tx_type {
                              PstTxType::SetKeys => {
                                if matches!(serai.keys(spec.set()).await, Ok(Some(_))) {
                                  log::info!("another coordinator set key pair for {:?}", set);
                                  break;
                                }
                              }
                              PstTxType::RemoveParticipant(removed) => {
                                if let Ok(Some(_)) = serai.keys(spec.set()).await {
                                  log::info!(
                                    "keys were set before we could publish removal for {:?}",
                                    hex::encode(removed)
                                  );
                                  break;
                                }

                                if let Ok(Some(participants)) =
                                  serai.participants(spec.set().network).await
                                {
                                  if !participants
                                    .iter()
                                    .any(|(participant, _)| participant.0 == removed)
                                  {
                                    log::info!(
                                      "another coordinator published removal for {:?}",
                                      hex::encode(removed)
                                    );
                                    break;
                                  }
                                }
                              }
                            }
                          }

                          log::error!(
                            "couldn't connect to Serai node to publish {tx_type:?} TX: {:?}",
                            e
                          );
                          tokio::time::sleep(core::time::Duration::from_secs(10)).await;
                        }
                      }
                    }
                  }
                },
                &|tx: Transaction| {
                  let tributary = tributary.clone();
                  async move {
                    match tributary.add_transaction(tx.clone()).await {
                      Ok(_) => {}
                      // Can happen as this occurs on a distinct DB TXN
                      Err(TransactionError::InvalidNonce) => {
                        log::warn!(
                          "publishing TX {tx:?} returned InvalidNonce. was it already added?"
                        )
                      }
                      Err(e) => panic!("created an invalid transaction: {e:?}"),
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
