#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{marker::PhantomData, future::Future};
use std::collections::HashMap;

use ciphersuite::group::GroupEncoding as _;
use dkg::Participant;

use serai_primitives::{
  BlockHash,
  validator_sets::{ExternalValidatorSet, Slash},
  crypto::SeraiNetworksAuxiliaryKey,
};

use serai_db::*;
use serai_task::ContinuallyRan;

use tributary_sdk::{
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
  Signed as TributarySigned, TransactionKind, TransactionTrait as _,
  Transaction as TributaryTransaction, Block, TributaryReader, P2p,
};

use serai_cosign_types::CosignIntent;
use serai_coordinator_substrate::TributaryValidatorSetInfo;

use messages::sign::{VariantSignId, SignId};

mod transaction;
pub use transaction::{SigningProtocolRound, Signed, Transaction};

mod db;
use db::*;
pub use db::Topic;

/// Test helpers for seeding DB state, generating random data, and constructing validator sets.
#[cfg(test)]
mod test_helpers;

#[cfg(test)]
mod tests;

/// Messages to send to the Processors.
pub struct ProcessorMessages;
impl ProcessorMessages {
  /// Try to receive a message to send to a Processor.
  pub fn try_recv(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<messages::CoordinatorMessage> {
    db::ProcessorMessages::try_recv(txn, set)
  }
}

/// Messages for the DKG confirmation.
pub struct DkgConfirmationMessages;
impl DkgConfirmationMessages {
  /// Receive a message for the DKG confirmation.
  ///
  /// These messages use the ProcessorMessage API as that's what existing flows are designed
  /// around, enabling their reuse. The ProcessorMessage includes a VariantSignId which isn't
  /// applicable to the DKG confirmation (as there's no such variant of the VariantSignId). The
  /// actual ID is undefined other than it will be consistent to the signing protocol and unique
  /// across validator sets, with no guarantees of uniqueness across contexts.
  pub fn try_recv(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<messages::sign::CoordinatorMessage> {
    db::DkgConfirmationMessages::try_recv(txn, set)
  }
}

/// The cosign intents.
pub struct CosignIntents;
impl CosignIntents {
  /// Provide a CosignIntent for this Tributary.
  ///
  /// This must be done before the associated `Transaction::Cosign` is provided.
  pub fn provide(txn: &mut impl DbTxn, set: ExternalValidatorSet, intent: &CosignIntent) {
    db::SubstrateCosignIntents::set(txn, set, intent.block_hash, intent);
  }
  fn take(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) -> Option<CosignIntent> {
    db::SubstrateCosignIntents::take(txn, set, substrate_block_hash)
  }
}

/// An interface to the topics recognized on this Tributary.
pub struct RecognizedTopics;
impl RecognizedTopics {
  /// If this topic has been recognized by this Tributary.
  ///
  /// This will either be by explicit recognition or participation.
  pub fn is_topic_recognized(getter: &impl Get, set: ExternalValidatorSet, topic: Topic) -> bool {
    TributaryDb::is_topic_recognized(getter, set, topic)
  }
  /// The next topic requiring recognition which has been recognized by this Tributary.
  pub fn try_recv_topic_requiring_recognition(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<Topic> {
    TributaryDb::try_recv_topic_requiring_recognition(txn, set)
  }
}

/// The plans to recognize upon a `Transaction::SubstrateBlock` being included on-chain.
pub struct SubstrateBlockPlans;
impl SubstrateBlockPlans {
  /// Set the plans to recognize upon the associated `Transaction::SubstrateBlock` being included
  /// on-chain.
  ///
  /// This must be done before the associated `Transaction::Cosign` is provided.
  pub fn set(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
    plans: &Vec<[u8; 32]>,
  ) {
    db::SubstrateBlockPlans::set(txn, set, substrate_block_hash, plans);
  }
  fn take(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) -> Option<Vec<[u8; 32]>> {
    db::SubstrateBlockPlans::take(txn, set, substrate_block_hash)
  }
}

struct ScanBlock<'a, TD: Db, TDT: DbTxn, P: P2p> {
  _td: PhantomData<TD>,
  _p2p: PhantomData<P>,
  tributary_txn: &'a mut TDT,
  tributary_validator_set_info: &'a TributaryValidatorSetInfo,
}
impl<TD: Db, TDT: DbTxn, P: P2p> ScanBlock<'_, TD, TDT, P> {
  fn potentially_start_cosign(&mut self) {
    let tributary_vset = self.tributary_validator_set_info.set;

    // Don't start a new cosigning instance if we're actively running one
    if TributaryDb::is_actively_cosigning(self.tributary_txn, tributary_vset) {
      return;
    }

    // Fetch the latest intended-to-be-cosigned block
    let Some(latest_substrate_block_to_cosign) =
      TributaryDb::latest_substrate_block_to_cosign(self.tributary_txn, tributary_vset)
    else {
      return;
    };

    // If it was already cosigned, return
    if TributaryDb::is_cosigned(
      self.tributary_txn,
      tributary_vset,
      latest_substrate_block_to_cosign,
    ) {
      return;
    }

    let intent =
      CosignIntents::take(self.tributary_txn, tributary_vset, latest_substrate_block_to_cosign)
        .expect("Transaction::Cosign locally provided but CosignIntents wasn't populated");
    assert_eq!(
      intent.block_hash, latest_substrate_block_to_cosign,
      "provided CosignIntent wasn't saved by its block hash"
    );

    // Mark us as actively cosigning
    TributaryDb::start_cosigning(
      self.tributary_txn,
      tributary_vset,
      latest_substrate_block_to_cosign,
      intent.block_number,
    );
    // Send the message for the processor to start signing
    TributaryDb::send_message(
      self.tributary_txn,
      tributary_vset,
      messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
        session: tributary_vset.session,
        cosign: intent.into_cosign(tributary_vset.network),
      },
    );
  }

  fn accumulate_dkg_confirmation<D: AsRef<[u8]> + Borshy>(
    &mut self,
    block_number: u64,
    topic: Topic,
    data: &D,
    participant: Participant,
  ) -> Option<(SignId, HashMap<Participant, Vec<u8>>)> {
    assert!(
      matches!(topic, Topic::DkgConfirmation { .. }),
      "`accumulate_dkg_confirmation` called with non-`DkgConfirmation` topic: {topic:?}"
    );
    match TributaryDb::accumulate::<D>(
      self.tributary_txn,
      self.tributary_validator_set_info,
      block_number,
      topic,
      participant,
      data,
    ) {
      DataSet::None => None,
      DataSet::Participating(data_set) => {
        let sign_id =
          topic.dkg_confirmation_sign_id(self.tributary_validator_set_info.set).unwrap();
        let data_set = data_set
          .into_iter()
          .map(|(participant, data)| (participant, data.as_ref().to_vec()))
          .collect();
        Some((sign_id, data_set))
      }
    }
  }

  fn handle_application_tx(&mut self, block_number: u64, tx: Transaction) {
    if let TransactionKind::Signed(_, TributarySigned { signer, .. }) = tx.kind() {
      let Some(participant) = self
        .tributary_validator_set_info
        .tributary_validator_set
        .get_consensus_index_by_serai_auxiliary(signer.to_bytes())
      else {
        // Ignore tx from unrecognized signer
        return;
      };

      // Verify the participant index in the Signed struct matches the signer's actual participant
      let signed = tx.signed().unwrap();
      if signed.participant != *participant {
        TributaryDb::fatal_slash(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          *participant,
          "signed participant index does not match signer",
        );
        return;
      }

      // Don't handle transactions from those fatally slashed
      // TODO: The fact they can publish these TXs makes this a notable spam vector
      if TributaryDb::is_fatally_slashed(
        self.tributary_txn,
        self.tributary_validator_set_info.set,
        *participant,
      ) {
        return;
      }
    }

    let topic = tx.topic();
    match tx {
      // Accumulate this vote and fatally slash the participant if past the threshold
      Transaction::RemoveParticipant { participant, signed } => {
        // Check the participant voted to be removed actually exists
        if self
          .tributary_validator_set_info
          .tributary_validator_set
          .get_tributary_validator_by_consensus_index(&participant)
          .is_none()
        {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.tributary_validator_set_info.set,
            signed.participant, // Or else slash the signer of this tx
            "voted to remove non-existent participant",
          );
          return;
        }

        match TributaryDb::accumulate(
          self.tributary_txn,
          self.tributary_validator_set_info,
          block_number,
          topic.unwrap(),
          signed.participant,
          &(),
        ) {
          DataSet::None => {}
          DataSet::Participating(_) => {
            TributaryDb::fatal_slash(
              self.tributary_txn,
              self.tributary_validator_set_info.set,
              participant,
              "voted to remove",
            );
          }
        }
      }

      // Send the participation to the processor
      Transaction::DkgParticipation { participation, signed } => {
        TributaryDb::send_message(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          messages::key_gen::CoordinatorMessage::Participation {
            session: self.tributary_validator_set_info.set.session,
            participant: signed.participant,
            participation,
          },
        );
      }
      Transaction::DkgConfirmationPreprocess { attempt: _, preprocess, signed } => {
        let topic = topic.unwrap();

        let Some((id, data_set)) =
          self.accumulate_dkg_confirmation(block_number, topic, &preprocess, signed.participant)
        else {
          return;
        };

        db::DkgConfirmationMessages::send(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          &messages::sign::CoordinatorMessage::Preprocesses { id, preprocesses: data_set },
        );
      }
      Transaction::DkgConfirmationShare { attempt: _, share, signed } => {
        let topic = topic.unwrap();

        let Some((id, data_set)) =
          self.accumulate_dkg_confirmation(block_number, topic, &share, signed.participant)
        else {
          return;
        };

        db::DkgConfirmationMessages::send(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          &messages::sign::CoordinatorMessage::Shares { id, shares: data_set },
        );
      }

      Transaction::Cosign { substrate_block_hash } => {
        // Update the latest intended-to-be-cosigned Substrate block
        TributaryDb::set_latest_substrate_block_to_cosign(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          substrate_block_hash,
        );
        // Start a new cosign if we aren't already working on one
        self.potentially_start_cosign();
      }
      Transaction::Cosigned { substrate_block_hash } => {
        /*
          We provide one Cosigned per Cosign transaction, but they have independent orders. This
          means we may receive Cosigned before Cosign. In order to ensure we only start work on
          not-yet-Cosigned cosigns, we flag all cosigned blocks as cosigned. Then, when we choose
          the next block to work on, we won't if it's already been cosigned.
        */
        TributaryDb::mark_cosigned(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          substrate_block_hash,
        );

        // If we aren't actively cosigning this block, return
        // This occurs when we have Cosign TXs A, B, C, we received Cosigned for A and start on C,
        // and then receive Cosigned for B
        if TributaryDb::get_actively_cosigning_hash(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
        ) != Some(substrate_block_hash)
        {
          return;
        }

        // Since this is the block we were cosigning, mark us as having finished cosigning
        TributaryDb::finish_cosigning(self.tributary_txn, self.tributary_validator_set_info.set);

        // Start working on the next cosign
        self.potentially_start_cosign();
      }
      Transaction::SubstrateBlock { hash } => {
        // Recognize all of the IDs this Substrate block causes to be signed
        let plans = SubstrateBlockPlans::take(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          hash,
        )
        .expect(
          "Transaction::SubstrateBlock locally provided but SubstrateBlockPlans wasn't populated",
        );
        for plan in plans {
          TributaryDb::recognize_topic(
            self.tributary_txn,
            self.tributary_validator_set_info.set,
            Topic::Sign {
              id: VariantSignId::Transaction(plan),
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
            },
          );
        }
      }
      Transaction::Batch { hash } => {
        // Recognize the signing of this batch
        TributaryDb::recognize_topic(
          self.tributary_txn,
          self.tributary_validator_set_info.set,
          Topic::Sign {
            id: VariantSignId::Batch(hash),
            attempt: 0,
            round: SigningProtocolRound::Preprocess,
          },
        );
      }

      Transaction::SlashReport { slash_points, signed } => {
        if slash_points.len() !=
          self
            .tributary_validator_set_info
            .tributary_validator_set
            .consensus_tributary_validators
            .len()
        {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.tributary_validator_set_info.set,
            signed.participant,
            "slash report was for a distinct amount of signers",
          );
          return;
        }

        // Accumulate, and if past the threshold, calculate *the* slash report and start signing it
        match TributaryDb::accumulate(
          self.tributary_txn,
          self.tributary_validator_set_info,
          block_number,
          topic.unwrap(),
          signed.participant,
          &slash_points,
        ) {
          DataSet::None => {}
          DataSet::Participating(data_set) => {
            // Find the median reported slashes for this validator
            /*
              TODO: This lets 34% perform a fatal slash. That shouldn't be allowed. We need
              to accept slash reports for a period past the threshold, and only fatally slash if we
              have a supermajority agree the slash should be fatal. If there isn't a supermajority,
              but the median believe the slash should be fatal, we need to fallback to a large
              constant.
            */
            let tributary_validators_len = self
              .tributary_validator_set_info
              .tributary_validator_set
              .consensus_tributary_validators
              .len();
            let mut median_slash_report = Vec::with_capacity(tributary_validators_len);
            for i in 0 .. tributary_validators_len {
              let mut reports_for_this_validator =
                data_set.values().map(|report| report[i]).collect::<Vec<_>>();
              reports_for_this_validator.sort_unstable();

              // Choose the median, where if there are two median values, the lower one is chosen
              let median_index = if (reports_for_this_validator.len() % 2) == 1 {
                reports_for_this_validator.len() / 2
              } else {
                (reports_for_this_validator.len() / 2) - 1
              };
              median_slash_report.push(reports_for_this_validator[median_index]);
            }

            // We only publish slashes for the `f` worst performers to:
            // 1) Effect amnesty if there were network disruptions which affected everyone
            // 2) Ensure the signing threshold doesn't have a disincentive to do their job

            // Find the worst performer within the signing threshold's slash points
            let f = (tributary_validators_len - 1) / 3;
            let worst_validator_in_supermajority_slash_points = {
              let mut sorted_slash_points = median_slash_report.clone();
              sorted_slash_points.sort_unstable();
              // This won't be a valid index if `f == 0`, which means we don't have any validators
              // to slash
              let index_of_first_validator_to_slash = tributary_validators_len - f;
              let index_of_worst_validator_in_supermajority = index_of_first_validator_to_slash - 1;
              sorted_slash_points[index_of_worst_validator_in_supermajority]
            };

            // Perform the amortization
            for slash_points in &mut median_slash_report {
              *slash_points =
                slash_points.saturating_sub(worst_validator_in_supermajority_slash_points);
            }
            let amortized_slash_report = median_slash_report;

            // Create the resulting slash report, only including validators who have non-zero
            // slash points after amortization
            let mut slash_report = vec![];
            for points in amortized_slash_report {
              // TODO: Natively store this as a `Slash`
              if points == u32::MAX {
                slash_report.push(Slash::Fatal);
              } else if points > 0 {
                slash_report.push(Slash::Points(points));
              }
            }
            assert!(
              slash_report.iter().filter(|points| !matches!(points, Slash::Points(0))).count() <= f
            );

            // Recognize the topic for signing the slash report
            TributaryDb::recognize_topic(
              self.tributary_txn,
              self.tributary_validator_set_info.set,
              Topic::Sign {
                id: VariantSignId::SlashReport,
                attempt: 0,
                round: SigningProtocolRound::Preprocess,
              },
            );
            // Send the message for the processor to start signing
            TributaryDb::send_message(
              self.tributary_txn,
              self.tributary_validator_set_info.set,
              messages::coordinator::CoordinatorMessage::SignSlashReport {
                session: self.tributary_validator_set_info.set.session,
                slash_report: slash_report.try_into().unwrap(),
              },
            );
          }
        }
      }

      Transaction::Sign { id: _, attempt: _, round, data, signed } => {
        let topic = topic.unwrap();

        if data.len() !=
          usize::from(
            self
              .tributary_validator_set_info
              .tributary_validator_set
              .get_tributary_validator_by_consensus_index(&signed.participant)
              .expect("signer not in tributary validator set list")
              .weight,
          )
        {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.tributary_validator_set_info.set,
            signed.participant,
            "signer signed for a participant not belonging to them",
          );
          return;
        }

        match TributaryDb::accumulate(
          self.tributary_txn,
          self.tributary_validator_set_info,
          block_number,
          topic,
          signed.participant,
          &data,
        ) {
          DataSet::None => {}
          DataSet::Participating(data_set) => {
            let sign_id = topic
              .sign_id(self.tributary_validator_set_info.set)
              .expect("Topic::Sign didn't have SignId");

            let flatten_data_set =
              |data_set: HashMap<Participant, HashMap<Participant, Vec<u8>>>| {
                let mut shares_per_validators_evrf_index = HashMap::with_capacity(usize::from(
                  self.tributary_validator_set_info.tributary_validator_set.total_weight(),
                ));

                for (i_consensus_participant, i_shares_by_participant) in data_set {
                  let this_validators_evrf_indexes = self
                    .tributary_validator_set_info
                    .tributary_validator_set
                    .get_evrf_indexes_by_consensus_index(&i_consensus_participant)
                    .expect("signer not in tributary validator set list");

                  assert_eq!(this_validators_evrf_indexes.len(), i_shares_by_participant.len());

                  for (i_evrf_index, share) in i_shares_by_participant {
                    shares_per_validators_evrf_index.insert(i_evrf_index, share);
                  }
                }
                shares_per_validators_evrf_index
              };
            let data_set = flatten_data_set(data_set);
            TributaryDb::send_message(
              self.tributary_txn,
              self.tributary_validator_set_info.set,
              match round {
                SigningProtocolRound::Preprocess => {
                  messages::sign::CoordinatorMessage::Preprocesses {
                    id: sign_id,
                    preprocesses: data_set,
                  }
                }
                SigningProtocolRound::Share => {
                  messages::sign::CoordinatorMessage::Shares { id: sign_id, shares: data_set }
                }
              },
            );
          }
        }
      }
    }
  }

  fn handle_block(mut self, block_number: u64, block: Block<Transaction>) {
    TributaryDb::start_of_block(
      self.tributary_txn,
      self.tributary_validator_set_info.set,
      block_number,
    );

    for tx in block.transactions {
      match tx {
        TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
          // Since the evidence is on the chain, it will have already been validated
          // We can just punish the signer
          let data = match ev {
            Evidence::ConflictingMessages(first, second) => (first, Some(second)),
            Evidence::InvalidPrecommit(first) | Evidence::InvalidValidRound(first) => (first, None),
          };
          let msgs = (
            decode_signed_message::<TendermintNetwork<TD, Transaction, P>>(&data.0).unwrap(),
            data.1.as_ref().map(|data| {
              decode_signed_message::<TendermintNetwork<TD, Transaction, P>>(data).unwrap()
            }),
          );

          if let Ok(senders_serai_auxiliary) =
            SeraiNetworksAuxiliaryKey::from_bytes(msgs.0.msg.sender)
          {
            if let Some(participant) = self
              .tributary_validator_set_info
              .tributary_validator_set
              .get_consensus_index_by_serai_auxiliary(senders_serai_auxiliary.to_bytes())
            {
              // Since anything with evidence is fundamentally faulty behavior, not just temporal
              // errors, mark the node as fatally slashed
              TributaryDb::fatal_slash(
                self.tributary_txn,
                self.tributary_validator_set_info.set,
                *participant,
                &format!("invalid tendermint messages: {msgs:?}"),
              );
            }
          }
        }
        TributaryTransaction::Application(tx) => {
          self.handle_application_tx(block_number, tx);
        }
      }
    }
  }
}

/// The task to scan the Tributary, populating `ProcessorMessages`.
pub struct ScanTributaryTask<TD: Db, P: P2p> {
  tributary_db: TD,
  set: TributaryValidatorSetInfo,
  tributary: TributaryReader<TD, Transaction>,
  _p2p: PhantomData<P>,
}

impl<TD: Db, P: P2p> ScanTributaryTask<TD, P> {
  /// Create a new instance of this task.
  ///
  /// This will panic if the Tributary read does not correspond to the set.
  pub fn new(
    tributary_db: TD,
    set: TributaryValidatorSetInfo,
    tributary: TributaryReader<TD, Transaction>,
  ) -> Self {
    ScanTributaryTask { tributary_db, set, tributary, _p2p: PhantomData }
  }
}

impl<TD: Db, P: P2p> ContinuallyRan for ScanTributaryTask<TD, P> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let (mut last_block_number, mut last_block_hash) =
        TributaryDb::last_handled_tributary_block(&self.tributary_db, self.set.set)
          .unwrap_or((0, self.tributary.genesis()));

      let mut made_progress = false;
      while let Some(block_hash) = self.tributary.block_after(&last_block_hash) {
        let block = self.tributary.block(&block_hash).unwrap();
        let block_number = last_block_number + 1;

        // Make sure we have all of the provided transactions for this block
        for tx in &block.transactions {
          let TransactionKind::Provided(order) = tx.kind() else {
            continue;
          };

          // make sure we have all the provided txs in this block locally
          if !self.tributary.locally_provided_txs_in_block(&block_hash, order) {
            return Err(format!(
              "didn't have the provided Transactions on-chain for set (ephemeral error): {:?}",
              self.set.set
            ));
          }
        }

        let mut tributary_txn = self.tributary_db.txn();
        (ScanBlock {
          _td: PhantomData::<TD>,
          _p2p: PhantomData::<P>,
          tributary_txn: &mut tributary_txn,
          tributary_validator_set_info: &self.set,
        })
        .handle_block(block_number, block);
        TributaryDb::set_last_handled_tributary_block(
          &mut tributary_txn,
          self.set.set,
          block_number,
          block_hash,
        );
        last_block_number = block_number;
        last_block_hash = block_hash;
        tributary_txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}

/// Create the `Transaction::SlashReport` to publish per the local view.
pub fn slash_report_transaction(getter: &impl Get, set: &TributaryValidatorSetInfo) -> Transaction {
  let mut slash_points =
    Vec::with_capacity(set.tributary_validator_set.consensus_tributary_validators.len());

  for i in 1 ..= set.tributary_validator_set.consensus_tributary_validators.len() {
    let i_participant = Participant::new(u16::try_from(i).unwrap()).unwrap();
    slash_points
      .push(ParticipantTributarySlashPoints::get(getter, set.set, i_participant).unwrap_or(0));
  }

  Transaction::SlashReport { slash_points, signed: Signed::default() }
}
