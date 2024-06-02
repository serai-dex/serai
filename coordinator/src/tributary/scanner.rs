use core::{marker::PhantomData, ops::Deref, future::Future, time::Duration};
use std::{sync::Arc, collections::HashSet};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use tokio::sync::broadcast;

use scale::{Encode, Decode};
use serai_client::{
  primitives::{SeraiAddress, Signature},
  validator_sets::primitives::{KeyPair, ValidatorSet},
  Serai,
};

use serai_db::DbTxn;

use processor_messages::coordinator::{SubstrateSignId, SubstrateSignableId};

use tributary::{
  TransactionKind, Transaction as TributaryTransaction, TransactionError, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
};

use crate::{Db, processors::Processors, substrate::BatchInstructionsHashDb, tributary::*, P2p};

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

#[async_trait::async_trait]
pub trait PublishSeraiTransaction {
  async fn publish_set_keys(
    &self,
    db: &(impl Sync + Get),
    set: ValidatorSet,
    removed: Vec<SeraiAddress>,
    key_pair: KeyPair,
    signature: Signature,
  );
}

mod impl_pst_for_serai {
  use super::*;

  use serai_client::SeraiValidatorSets;

  // Uses a macro because Rust can't resolve the lifetimes/generics around the check function
  // check is expected to return true if the effect has already occurred
  // The generated publish function will return true if *we* published the transaction
  macro_rules! common_pst {
    ($Meta: ty, $check: ident) => {
      async fn publish(
        serai: &Serai,
        db: &impl Get,
        set: ValidatorSet,
        tx: serai_client::Transaction,
        meta: $Meta,
      ) -> bool {
        loop {
          match serai.publish(&tx).await {
            Ok(_) => return true,
            // This is assumed to be some ephemeral error due to the assumed fault-free
            // creation
            // TODO2: Differentiate connection errors from invariants
            Err(e) => {
              // The following block is irrelevant, and can/likely will fail, if we're publishing
              // a TX for an old session
              // If we're on a newer session, move on
              if crate::RetiredTributaryDb::get(db, set).is_some() {
                log::warn!("trying to publish a TX relevant to set {set:?} which isn't the latest");
                return false;
              }

              if let Ok(serai) = serai.as_of_latest_finalized_block().await {
                let serai = serai.validator_sets();

                // Check if someone else published the TX in question
                if $check(serai, set, meta).await {
                  return false;
                }
              }

              log::error!("couldn't connect to Serai node to publish TX: {e:?}");
              tokio::time::sleep(core::time::Duration::from_secs(5)).await;
            }
          }
        }
      }
    };
  }

  #[async_trait::async_trait]
  impl PublishSeraiTransaction for Serai {
    async fn publish_set_keys(
      &self,
      db: &(impl Sync + Get),
      set: ValidatorSet,
      removed: Vec<SeraiAddress>,
      key_pair: KeyPair,
      signature: Signature,
    ) {
      // TODO: BoundedVec as an arg to avoid this expect
      let tx = SeraiValidatorSets::set_keys(
        set.network,
        removed.try_into().expect("removing more than allowed"),
        key_pair,
        signature,
      );
      async fn check(serai: SeraiValidatorSets<'_>, set: ValidatorSet, (): ()) -> bool {
        if matches!(serai.keys(set).await, Ok(Some(_))) {
          log::info!("another coordinator set key pair for {:?}", set);
          return true;
        }
        false
      }
      common_pst!((), check);
      if publish(self, db, set, tx, ()).await {
        log::info!("published set keys for {set:?}");
      }
    }
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
  D: Db,
  T: DbTxn,
  Pro: Processors,
  PST: PublishSeraiTransaction,
  PTT: PTTTrait,
  RID: RIDTrait,
  P: P2p,
> {
  pub db: &'a D,
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

impl<
    D: Db,
    T: DbTxn,
    Pro: Processors,
    PST: PublishSeraiTransaction,
    PTT: PTTTrait,
    RID: RIDTrait,
    P: P2p,
  > TributaryBlockHandler<'_, D, T, Pro, PST, PTT, RID, P>
{
  pub fn fatal_slash(&mut self, slashing: [u8; 32], reason: &str) {
    let genesis = self.spec.genesis();

    log::warn!("fatally slashing {}. reason: {}", hex::encode(slashing), reason);
    FatallySlashed::set_fatally_slashed(self.txn, genesis, slashing);

    // TODO: disconnect the node from network/ban from further participation in all Tributaries
  }

  // TODO: Once Substrate confirms a key, we need to rotate our validator set OR form a second
  // Tributary post-DKG
  // https://github.com/serai-dex/serai/issues/426

  async fn handle(mut self) {
    log::info!("found block for Tributary {:?}", self.spec.set());

    let transactions = self.block.transactions.clone();
    for tx in transactions {
      match tx {
        TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
          // Since the evidence is on the chain, it should already have been validated
          // We can just punish the signer
          let data = match ev {
            Evidence::ConflictingMessages(first, second) => (first, Some(second)),
            Evidence::InvalidPrecommit(first) | Evidence::InvalidValidRound(first) => (first, None),
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
          self.fatal_slash(msgs.0.msg.sender, &format!("invalid tendermint messages: {msgs:?}"));
        }
        TributaryTransaction::Application(tx) => {
          self.handle_application_tx(tx).await;
        }
      }
    }

    let genesis = self.spec.genesis();

    let current_fatal_slashes = FatalSlashes::get_as_keys(self.txn, genesis);

    // Calculate the shares still present, spinning if not enough are
    // still_present_shares is used by a below branch, yet it's a natural byproduct of checking if
    // we should spin, hence storing it in a variable here
    let still_present_shares = {
      // Start with the original n value
      let mut present_shares = self.spec.n(&[]);
      // Remove everyone fatally slashed
      for removed in &current_fatal_slashes {
        let original_i_for_removed =
          self.spec.i(&[], *removed).expect("removed party was never present");
        let removed_shares =
          u16::from(original_i_for_removed.end) - u16::from(original_i_for_removed.start);
        present_shares -= removed_shares;
      }

      // Spin if the present shares don't satisfy the required threshold
      if present_shares < self.spec.t() {
        loop {
          log::error!(
            "fatally slashed so many participants for {:?} we no longer meet the threshold",
            self.spec.set()
          );
          tokio::time::sleep(core::time::Duration::from_secs(60)).await;
        }
      }

      present_shares
    };

    for topic in ReattemptDb::take(self.txn, genesis, self.block_number) {
      let attempt = AttemptDb::start_next_attempt(self.txn, genesis, topic);
      log::info!("re-attempting {topic:?} with attempt {attempt}");

      // Slash people who failed to participate as expected in the prior attempt
      {
        let prior_attempt = attempt - 1;
        let (removed, expected_participants) = match topic {
          Topic::Dkg => {
            // Every validator who wasn't removed is expected to have participated
            let removed =
              crate::tributary::removed_as_of_dkg_attempt(self.txn, genesis, prior_attempt)
                .expect("prior attempt didn't have its removed saved to disk");
            let removed_set = removed.iter().copied().collect::<HashSet<_>>();
            (
              removed,
              self
                .spec
                .validators()
                .into_iter()
                .filter_map(|(validator, _)| {
                  Some(validator).filter(|validator| !removed_set.contains(validator))
                })
                .collect(),
            )
          }
          Topic::DkgConfirmation => {
            panic!("TODO: re-attempting DkgConfirmation when we should be re-attempting the Dkg")
          }
          Topic::SubstrateSign(_) | Topic::Sign(_) => {
            let removed =
              crate::tributary::removed_as_of_set_keys(self.txn, self.spec.set(), genesis)
                .expect("SubstrateSign/Sign yet have yet to set keys");
            // TODO: If 67% sent preprocesses, this should be them. Else, this should be vec![]
            let expected_participants = vec![];
            (removed, expected_participants)
          }
        };

        let (expected_topic, expected_label) = match topic {
          Topic::Dkg => {
            let n = self.spec.n(&removed);
            // If we got all the DKG shares, we should be on DKG confirmation
            let share_spec =
              DataSpecification { topic: Topic::Dkg, label: Label::Share, attempt: prior_attempt };
            if DataReceived::get(self.txn, genesis, &share_spec).unwrap_or(0) == n {
              // Label::Share since there is no Label::Preprocess for DkgConfirmation since the
              // preprocess is part of Topic::Dkg Label::Share
              (Topic::DkgConfirmation, Label::Share)
            } else {
              let preprocess_spec = DataSpecification {
                topic: Topic::Dkg,
                label: Label::Preprocess,
                attempt: prior_attempt,
              };
              // If we got all the DKG preprocesses, DKG shares
              if DataReceived::get(self.txn, genesis, &preprocess_spec).unwrap_or(0) == n {
                // Label::Share since there is no Label::Preprocess for DkgConfirmation since the
                // preprocess is part of Topic::Dkg Label::Share
                (Topic::Dkg, Label::Share)
              } else {
                (Topic::Dkg, Label::Preprocess)
              }
            }
          }
          Topic::DkgConfirmation => unreachable!(),
          // If we got enough participants to move forward, then we expect shares from them all
          Topic::SubstrateSign(_) | Topic::Sign(_) => (topic, Label::Share),
        };

        let mut did_not_participate = vec![];
        for expected_participant in expected_participants {
          if DataDb::get(
            self.txn,
            genesis,
            &DataSpecification {
              topic: expected_topic,
              label: expected_label,
              attempt: prior_attempt,
            },
            &expected_participant.to_bytes(),
          )
          .is_none()
          {
            did_not_participate.push(expected_participant);
          }
        }

        // If a supermajority didn't participate as expected, the protocol was likely aborted due
        // to detection of a completion or some larger networking error
        // Accordingly, clear did_not_participate
        // TODO

        // If during the DKG, explicitly mark these people as having been offline
        // TODO: If they were offline sufficiently long ago, don't strike them off
        if topic == Topic::Dkg {
          let mut existing = OfflineDuringDkg::get(self.txn, genesis).unwrap_or(vec![]);
          for did_not_participate in did_not_participate {
            existing.push(did_not_participate.to_bytes());
          }
          OfflineDuringDkg::set(self.txn, genesis, &existing);
        }

        // Slash everyone who didn't participate as expected
        // This may be overzealous as if a minority detects a completion, they'll abort yet the
        // supermajority will cause the above allowance to not trigger, causing an honest minority
        // to be slashed
        // At the end of the protocol, the accumulated slashes are reduced by the amount obtained
        // by the worst-performing member of the supermajority, and this is expected to
        // sufficiently compensate for slashes which occur under normal operation
        // TODO
      }

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
          let mut removed = current_fatal_slashes.clone();

          let t = self.spec.t();
          {
            let mut present_shares = still_present_shares;

            // Load the parties marked as offline across the various attempts
            let mut offline = OfflineDuringDkg::get(self.txn, genesis)
              .unwrap_or(vec![])
              .iter()
              .map(|key| <Ristretto as Ciphersuite>::G::from_bytes(key).unwrap())
              .collect::<Vec<_>>();
            // Pop from the list to prioritize the removal of those recently offline
            while let Some(offline) = offline.pop() {
              // Make sure they weren't removed already (such as due to being fatally slashed)
              // This also may trigger if they were offline across multiple attempts
              if removed.contains(&offline) {
                continue;
              }

              // If we can remove them and still meet the threshold, do so
              let original_i_for_offline =
                self.spec.i(&[], offline).expect("offline was never present?");
              let offline_shares =
                u16::from(original_i_for_offline.end) - u16::from(original_i_for_offline.start);
              if (present_shares - offline_shares) >= t {
                present_shares -= offline_shares;
                removed.push(offline);
              }

              // If we've removed as many people as we can, break
              if present_shares == t {
                break;
              }
            }
          }

          RemovedAsOfDkgAttempt::set(
            self.txn,
            genesis,
            attempt,
            &removed.iter().map(<Ristretto as Ciphersuite>::G::to_bytes).collect(),
          );

          if DkgLocallyCompleted::get(self.txn, genesis).is_none() {
            let Some(our_i) = self.spec.i(&removed, Ristretto::generator() * self.our_key.deref())
            else {
              continue;
            };

            // Since it wasn't completed, instruct the processor to start the next attempt
            let id =
              processor_messages::key_gen::KeyGenId { session: self.spec.set().session, attempt };

            let params =
              frost::ThresholdParams::new(t, self.spec.n(&removed), our_i.start).unwrap();
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
        Topic::DkgConfirmation => unreachable!(),
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
                  .map_or(0, |cosign| cosign.block_number);
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
              // If the Batch hasn't appeared on-chain...
              if BatchInstructionsHashDb::get(self.txn, self.spec.set().network, batch).is_none() {
                // Instruct the processor to start the next attempt
                // The processor won't continue if it's already signed a Batch
                // Prior checking if the Batch is on-chain just may reduce the non-participating
                // 33% from publishing their re-attempt messages
                self
                  .processors
                  .send(
                    self.spec.set().network,
                    processor_messages::coordinator::CoordinatorMessage::BatchReattempt { id },
                  )
                  .await;
              }
            }
            SubstrateSignableId::SlashReport => {
              // If this Tributary hasn't been retired...
              // (published SlashReport/took too long to do so)
              if crate::RetiredTributaryDb::get(self.txn, self.spec.set()).is_none() {
                let report = SlashReport::get(self.txn, self.spec.set())
                  .expect("re-attempting signing a SlashReport we don't have?");
                self
                  .processors
                  .send(
                    self.spec.set().network,
                    processor_messages::coordinator::CoordinatorMessage::SignSlashReport {
                      id,
                      report,
                    },
                  )
                  .await;
              }
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

    if Some(u64::from(self.block_number)) == SlashReportCutOff::get(self.txn, genesis) {
      // Grab every slash report
      let mut all_reports = vec![];
      for (i, (validator, _)) in self.spec.validators().into_iter().enumerate() {
        let Some(mut report) = SlashReports::get(self.txn, genesis, validator.to_bytes()) else {
          continue;
        };
        // Assign them 0 points for themselves
        report.insert(i, 0);
        // Uses &[] as we only need the length which is independent to who else was removed
        let signer_i = self.spec.i(&[], validator).unwrap();
        let signer_len = u16::from(signer_i.end) - u16::from(signer_i.start);
        // Push `n` copies, one for each of their shares
        for _ in 0 .. signer_len {
          all_reports.push(report.clone());
        }
      }

      // For each participant, grab their median
      let mut medians = vec![];
      for p in 0 .. self.spec.validators().len() {
        let mut median_calc = vec![];
        for report in &all_reports {
          median_calc.push(report[p]);
        }
        median_calc.sort_unstable();
        medians.push(median_calc[median_calc.len() / 2]);
      }

      // Grab the points of the last party within the best-performing threshold
      // This is done by first expanding the point values by the amount of shares
      let mut sorted_medians = vec![];
      for (i, (_, shares)) in self.spec.validators().into_iter().enumerate() {
        for _ in 0 .. shares {
          sorted_medians.push(medians[i]);
        }
      }
      // Then performing the sort
      sorted_medians.sort_unstable();
      let worst_points_by_party_within_threshold = sorted_medians[usize::from(self.spec.t()) - 1];

      // Reduce everyone's points by this value
      for median in &mut medians {
        *median = median.saturating_sub(worst_points_by_party_within_threshold);
      }

      // The threshold now has the proper incentive to report this as they no longer suffer
      // negative effects
      //
      // Additionally, if all validators had degraded performance, they don't all get penalized for
      // what's likely outside their control (as it occurred universally)

      // Mark everyone fatally slashed with u32::MAX
      for (i, (validator, _)) in self.spec.validators().into_iter().enumerate() {
        if FatallySlashed::get(self.txn, genesis, validator.to_bytes()).is_some() {
          medians[i] = u32::MAX;
        }
      }

      let mut report = vec![];
      for (i, (validator, _)) in self.spec.validators().into_iter().enumerate() {
        if medians[i] != 0 {
          report.push((validator.to_bytes(), medians[i]));
        }
      }

      // This does lock in the report, meaning further slash point accumulations won't be reported
      // They still have value to be locally tracked due to local decisions made based off
      // accumulated slash reports
      SlashReport::set(self.txn, self.spec.set(), &report);

      // Start a signing protocol for this
      self
        .processors
        .send(
          self.spec.set().network,
          processor_messages::coordinator::CoordinatorMessage::SignSlashReport {
            id: SubstrateSignId {
              session: self.spec.set().session,
              id: SubstrateSignableId::SlashReport,
              attempt: 0,
            },
            report,
          },
        )
        .await;
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_new_blocks<
  D: Db,
  Pro: Processors,
  PST: PublishSeraiTransaction,
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

    let mut db_clone = db.clone();
    let mut txn = db_clone.txn();
    TributaryBlockNumber::set(&mut txn, next, &block_number);
    (TributaryBlockHandler {
      db,
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
    .handle()
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
                &*serai,
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
