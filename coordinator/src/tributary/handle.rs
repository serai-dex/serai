use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::dkg::Participant;

use scale::{Encode, Decode};
use serai_client::{Signature, validator_sets::primitives::KeyPair};

use tributary::{Signed, TransactionKind, TransactionTrait};

use processor_messages::{
  key_gen::self,
  coordinator::{self, SubstrateSignableId, SubstrateSignId},
  sign::{self, SignId},
};

use serai_db::*;

use crate::{
  processors::Processors,
  tributary::{
    *,
    signing_protocol::DkgConfirmer,
    scanner::{
      RecognizedIdType, RIDTrait, PublishSeraiTransaction, PTTTrait, TributaryBlockHandler,
    },
  },
  P2p,
};

pub fn dkg_confirmation_nonces(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  txn: &mut impl DbTxn,
  attempt: u32,
) -> [u8; 64] {
  DkgConfirmer::new(key, spec, txn, attempt).preprocess()
}

pub fn generated_key_pair<D: Db>(
  txn: &mut D::Transaction<'_>,
  genesis: [u8; 32],
  key_pair: &KeyPair,
) {
  DkgKeyPair::set(txn, genesis, key_pair);
}

fn unflatten(spec: &TributarySpec, data: &mut HashMap<Participant, Vec<u8>>) {
  for (validator, _) in spec.validators() {
    let Some(range) = spec.i(validator) else { continue };
    let Some(all_segments) = data.remove(&range.start) else {
      continue;
    };
    let mut data_vec = Vec::<_>::decode(&mut all_segments.as_slice()).unwrap();
    for i in u16::from(range.start) .. u16::from(range.end) {
      let i = Participant::new(i).unwrap();
      data.insert(i, data_vec.remove(0));
    }
  }
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
  fn accumulate(
    &mut self,
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &Vec<u8>,
  ) -> Accumulation {
    log::debug!("accumulating entry for {:?} attempt #{}", &data_spec.topic, &data_spec.attempt);
    let genesis = self.spec.genesis();
    if DataDb::get(self.txn, genesis, data_spec, &signer.to_bytes()).is_some() {
      panic!("accumulating data for a participant multiple times");
    }
    let signer_shares = {
      let signer_i = self.spec.i(signer).expect("transaction signer wasn't a member of the set");
      u16::from(signer_i.end) - u16::from(signer_i.start)
    };

    let prior_received = DataReceived::get(self.txn, genesis, data_spec).unwrap_or_default();
    let now_received = prior_received + signer_shares;
    DataReceived::set(self.txn, genesis, data_spec, &now_received);
    DataDb::set(self.txn, genesis, data_spec, &signer.to_bytes(), data);

    let received_range = (prior_received + 1) ..= now_received;

    // If 2/3rds of the network participated in this preprocess, queue it for an automatic
    // re-attempt
    if (data_spec.label == Label::Preprocess) && received_range.contains(&self.spec.t()) {
      // Double check the attempt on this entry, as we don't want to schedule a re-attempt if this
      // is an old entry
      // This is an assert, not part of the if check, as old data shouldn't be here in the first
      // place
      assert_eq!(AttemptDb::attempt(self.txn, genesis, data_spec.topic), Some(data_spec.attempt));
      ReattemptDb::schedule_reattempt(self.txn, genesis, self.block_number, data_spec.topic);
    }

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    if received_range.contains(&self.spec.t()) {
      log::debug!(
        "accumulation for entry {:?} attempt #{} is ready",
        &data_spec.topic,
        &data_spec.attempt
      );

      let mut data = HashMap::new();
      for validator in self.spec.validators().iter().map(|validator| validator.0) {
        let Some(i) = self.spec.i(validator) else { continue };
        data.insert(
          i.start,
          if let Some(data) = DataDb::get(self.txn, genesis, data_spec, &validator.to_bytes()) {
            data
          } else {
            continue;
          },
        );
      }

      assert_eq!(data.len(), usize::from(self.spec.t()));

      // Remove our own piece of data, if we were involved
      if let Some(i) = self.spec.i(Ristretto::generator() * self.our_key.deref()) {
        if data.remove(&i.start).is_some() {
          return Accumulation::Ready(DataSet::Participating(data));
        }
      }
      return Accumulation::Ready(DataSet::NotParticipating);
    }
    Accumulation::NotReady
  }

  fn handle_data(
    &mut self,
    data_spec: &DataSpecification,
    bytes: &Vec<u8>,
    signed: &Signed,
  ) -> Accumulation {
    let genesis = self.spec.genesis();

    let Some(curr_attempt) = AttemptDb::attempt(self.txn, genesis, data_spec.topic) else {
      // Premature publication of a valid ID/publication of an invalid ID
      self.fatal_slash(signed.signer.to_bytes(), "published data for ID without an attempt");
      return Accumulation::NotReady;
    };

    // If they've already published a TX for this attempt, slash
    // This shouldn't be reachable since nonces were made inserted by the coordinator, yet it's a
    // cheap check to leave in for safety
    if DataDb::get(self.txn, genesis, data_spec, &signed.signer.to_bytes()).is_some() {
      self.fatal_slash(signed.signer.to_bytes(), "published data multiple times");
      return Accumulation::NotReady;
    }

    // If the attempt is lesser than the blockchain's, return
    if data_spec.attempt < curr_attempt {
      log::debug!(
        "dated attempt published onto tributary for topic {:?} (used attempt {}, current {})",
        data_spec.topic,
        data_spec.attempt,
        curr_attempt
      );
      return Accumulation::NotReady;
    }
    // If the attempt is greater, this is a premature publication, full slash
    if data_spec.attempt > curr_attempt {
      self.fatal_slash(
        signed.signer.to_bytes(),
        "published data with an attempt which hasn't started",
      );
      return Accumulation::NotReady;
    }

    // TODO: We can also full slash if shares before all commitments, or share before the
    // necessary preprocesses

    // TODO: If this is shares, we need to check they are part of the selected signing set

    // Accumulate this data
    self.accumulate(data_spec, signed.signer, bytes)
  }

  fn check_sign_data_len(
    &mut self,
    signer: <Ristretto as Ciphersuite>::G,
    len: usize,
  ) -> Result<(), ()> {
    let signer_i = self.spec.i(signer).expect("signer wasn't a member of the set");
    if len != usize::from(u16::from(signer_i.end) - u16::from(signer_i.start)) {
      self.fatal_slash(
        signer.to_bytes(),
        "signer published a distinct amount of sign data than they had shares",
      );
      Err(())?;
    }
    Ok(())
  }

  // TODO: Don't call fatal_slash in here, return the party to fatal_slash to ensure no further
  // execution occurs
  pub(crate) async fn handle_application_tx(&mut self, tx: Transaction) {
    let genesis = self.spec.genesis();

    // Don't handle transactions from fatally slashed participants
    // This prevents removed participants from sabotaging the removal signing sessions and so on
    // TODO: Because fatally slashed participants can still publish onto the blockchain, they have
    // a notable DoS ability
    if let TransactionKind::Signed(_, signed) = tx.kind() {
      if FatallySlashed::get(self.txn, genesis, signed.signer.to_bytes()).is_some() {
        return;
      }
    }

    match tx {
      Transaction::RemoveParticipant { participant, signed } => {
        if self.spec.i(participant).is_none() {
          self.fatal_slash(participant.to_bytes(), "RemoveParticipant vote for non-validator");
          return;
        }

        let participant = participant.to_bytes();
        let signer = signed.signer.to_bytes();

        assert!(
          VotedToRemove::get(self.txn, genesis, signer, participant).is_none(),
          "VotedToRemove multiple times despite a single nonce being allocated",
        );
        VotedToRemove::set(self.txn, genesis, signer, participant, &());

        let prior_votes = VotesToRemove::get(self.txn, genesis, participant).unwrap_or(0);
        let signer_votes =
          self.spec.i(signed.signer).expect("signer wasn't a validator for this network?");
        let new_votes = prior_votes + u16::from(signer_votes.end) - u16::from(signer_votes.start);
        VotesToRemove::set(self.txn, genesis, participant, &new_votes);
        if ((prior_votes + 1) ..= new_votes).contains(&self.spec.t()) {
          self.fatal_slash(participant, "RemoveParticipant vote")
        }
      }

      Transaction::DkgParticipation { participation, signed } => {
        // Send the participation to the processor
        self
          .processors
          .send(
            self.spec.set().network,
            key_gen::CoordinatorMessage::Participation {
              session: self.spec.set().session,
              participant: self
                .spec
                .i(signed.signer)
                .expect("signer wasn't a validator for this network?")
                .start,
              participation,
            },
          )
          .await;
      }

      Transaction::DkgConfirmationNonces { attempt, confirmation_nonces, signed } => {
        let data_spec =
          DataSpecification { topic: Topic::DkgConfirmation, label: Label::Preprocess, attempt };
        match self.handle_data(&data_spec, &confirmation_nonces.to_vec(), &signed) {
          Accumulation::Ready(DataSet::Participating(confirmation_nonces)) => {
            log::info!(
              "got all DkgConfirmationNonces for {}, attempt {attempt}",
              hex::encode(genesis)
            );

            ConfirmationNonces::set(self.txn, genesis, attempt, &confirmation_nonces);

            // Send the expected DkgConfirmationShare
            // TODO: Slight race condition here due to set, publish tx, then commit txn
            let key_pair = DkgKeyPair::get(self.txn, genesis)
              .expect("participating in confirming key we don't have");
            let mut tx = match DkgConfirmer::new(self.our_key, self.spec, self.txn, attempt)
              .share(confirmation_nonces, &key_pair)
            {
              Ok(confirmation_share) => Transaction::DkgConfirmationShare {
                attempt,
                confirmation_share,
                signed: Transaction::empty_signed(),
              },
              Err(participant) => Transaction::RemoveParticipant {
                participant: self.spec.reverse_lookup_i(participant).unwrap(),
                signed: Transaction::empty_signed(),
              },
            };
            tx.sign(&mut OsRng, genesis, self.our_key);
            self.publish_tributary_tx.publish_tributary_tx(tx).await;
          }
          Accumulation::Ready(DataSet::NotParticipating) | Accumulation::NotReady => {}
        }
      }

      Transaction::DkgConfirmationShare { attempt, confirmation_share, signed } => {
        let data_spec =
          DataSpecification { topic: Topic::DkgConfirmation, label: Label::Share, attempt };
        match self.handle_data(&data_spec, &confirmation_share.to_vec(), &signed) {
          Accumulation::Ready(DataSet::Participating(shares)) => {
            log::info!(
              "got all DkgConfirmationShare for {}, attempt {attempt}",
              hex::encode(genesis)
            );

            let preprocesses = ConfirmationNonces::get(self.txn, genesis, attempt).unwrap();

            // TODO: This can technically happen under very very very specific timing as the txn
            // put happens before DkgConfirmationShare, yet the txn isn't guaranteed to be
            // committed
            let key_pair = DkgKeyPair::get(self.txn, genesis).expect(
              "in DkgConfirmationShare handling, which happens after everyone \
              (including us) fires DkgConfirmationShare, yet no confirming key pair",
            );

            // Determine the bitstring representing who participated before we move `shares`
            let validators = self.spec.validators();
            let mut signature_participants = bitvec::vec::BitVec::with_capacity(validators.len());
            for (participant, _) in validators {
              signature_participants.push(
                (participant == (<Ristretto as Ciphersuite>::generator() * self.our_key.deref())) ||
                  shares.contains_key(&self.spec.i(participant).unwrap().start),
              );
            }

            // Produce the final signature
            let mut confirmer = DkgConfirmer::new(self.our_key, self.spec, self.txn, attempt);
            let sig = match confirmer.complete(preprocesses, &key_pair, shares) {
              Ok(sig) => sig,
              Err(p) => {
                let mut tx = Transaction::RemoveParticipant {
                  participant: self.spec.reverse_lookup_i(p).unwrap(),
                  signed: Transaction::empty_signed(),
                };
                tx.sign(&mut OsRng, genesis, self.our_key);
                self.publish_tributary_tx.publish_tributary_tx(tx).await;
                return;
              }
            };

            self
              .publish_serai_tx
              .publish_set_keys(
                self.db,
                self.spec.set(),
                key_pair,
                signature_participants,
                Signature(sig),
              )
              .await;
          }
          Accumulation::Ready(DataSet::NotParticipating) | Accumulation::NotReady => {}
        }
      }

      Transaction::CosignSubstrateBlock(hash) => {
        AttemptDb::recognize_topic(
          self.txn,
          genesis,
          Topic::SubstrateSign(SubstrateSignableId::CosigningSubstrateBlock(hash)),
        );

        let block_number = SeraiBlockNumber::get(self.txn, hash)
          .expect("CosignSubstrateBlock yet didn't save Serai block number");
        let msg = coordinator::CoordinatorMessage::CosignSubstrateBlock {
          id: SubstrateSignId {
            session: self.spec.set().session,
            id: SubstrateSignableId::CosigningSubstrateBlock(hash),
            attempt: 0,
          },
          block_number,
        };
        self.processors.send(self.spec.set().network, msg).await;
      }

      Transaction::Batch { block: _, batch } => {
        // Because this Batch has achieved synchrony, its batch ID should be authorized
        AttemptDb::recognize_topic(
          self.txn,
          genesis,
          Topic::SubstrateSign(SubstrateSignableId::Batch(batch)),
        );
        self
          .recognized_id
          .recognized_id(
            self.spec.set(),
            genesis,
            RecognizedIdType::Batch,
            batch.to_le_bytes().to_vec(),
          )
          .await;
      }

      Transaction::SubstrateBlock(block) => {
        let plan_ids = PlanIds::get(self.txn, &genesis, block).expect(
          "synced a tributary block finalizing a substrate block in a provided transaction \
          despite us not providing that transaction",
        );

        for id in plan_ids {
          AttemptDb::recognize_topic(self.txn, genesis, Topic::Sign(id));
          self
            .recognized_id
            .recognized_id(self.spec.set(), genesis, RecognizedIdType::Plan, id.to_vec())
            .await;
        }
      }

      Transaction::SubstrateSign(data) => {
        let signer = data.signed.signer;
        let Ok(()) = self.check_sign_data_len(signer, data.data.len()) else {
          return;
        };
        let expected_len = match data.label {
          Label::Preprocess => 64,
          Label::Share => 32,
        };
        for data in &data.data {
          if data.len() != expected_len {
            self.fatal_slash(
              signer.to_bytes(),
              "unexpected length data for substrate signing protocol",
            );
            return;
          }
        }

        let data_spec = DataSpecification {
          topic: Topic::SubstrateSign(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        let Accumulation::Ready(DataSet::Participating(mut results)) =
          self.handle_data(&data_spec, &data.data.encode(), &data.signed)
        else {
          return;
        };
        unflatten(self.spec, &mut results);

        let id = SubstrateSignId {
          session: self.spec.set().session,
          id: data.plan,
          attempt: data.attempt,
        };
        let msg = match data.label {
          Label::Preprocess => coordinator::CoordinatorMessage::SubstratePreprocesses {
            id,
            preprocesses: results.into_iter().map(|(v, p)| (v, p.try_into().unwrap())).collect(),
          },
          Label::Share => coordinator::CoordinatorMessage::SubstrateShares {
            id,
            shares: results.into_iter().map(|(v, p)| (v, p.try_into().unwrap())).collect(),
          },
        };
        self.processors.send(self.spec.set().network, msg).await;
      }

      Transaction::Sign(data) => {
        let Ok(()) = self.check_sign_data_len(data.signed.signer, data.data.len()) else {
          return;
        };

        let data_spec = DataSpecification {
          topic: Topic::Sign(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        if let Accumulation::Ready(DataSet::Participating(mut results)) =
          self.handle_data(&data_spec, &data.data.encode(), &data.signed)
        {
          unflatten(self.spec, &mut results);
          let id =
            SignId { session: self.spec.set().session, id: data.plan, attempt: data.attempt };
          self
            .processors
            .send(
              self.spec.set().network,
              match data.label {
                Label::Preprocess => {
                  sign::CoordinatorMessage::Preprocesses { id, preprocesses: results }
                }
                Label::Share => sign::CoordinatorMessage::Shares { id, shares: results },
              },
            )
            .await;
        }
      }

      Transaction::SignCompleted { plan, tx_hash, first_signer, signature: _ } => {
        log::info!(
          "on-chain SignCompleted claims {} completes {}",
          hex::encode(&tx_hash),
          hex::encode(plan)
        );

        if AttemptDb::attempt(self.txn, genesis, Topic::Sign(plan)).is_none() {
          self.fatal_slash(first_signer.to_bytes(), "claimed an unrecognized plan was completed");
          return;
        };

        // TODO: Confirm this signer hasn't prior published a completion

        let msg = sign::CoordinatorMessage::Completed {
          session: self.spec.set().session,
          id: plan,
          tx: tx_hash,
        };
        self.processors.send(self.spec.set().network, msg).await;
      }

      Transaction::SlashReport(points, signed) => {
        let signer_range = self.spec.i(signed.signer).unwrap();
        let signer_len = u16::from(signer_range.end) - u16::from(signer_range.start);
        if points.len() != (self.spec.validators().len() - 1) {
          self.fatal_slash(
            signed.signer.to_bytes(),
            "submitted a distinct amount of slash points to participants",
          );
          return;
        }

        if SlashReports::get(self.txn, genesis, signed.signer.to_bytes()).is_some() {
          self.fatal_slash(signed.signer.to_bytes(), "submitted multiple slash points");
          return;
        }
        SlashReports::set(self.txn, genesis, signed.signer.to_bytes(), &points);

        let prior_reported = SlashReported::get(self.txn, genesis).unwrap_or(0);
        let now_reported = prior_reported + signer_len;
        SlashReported::set(self.txn, genesis, &now_reported);

        if (prior_reported < self.spec.t()) && (now_reported >= self.spec.t()) {
          SlashReportCutOff::set(
            self.txn,
            genesis,
            // 30 minutes into the future
            &(u64::from(self.block_number) +
              ((30 * 60 * 1000) / u64::from(tributary::tendermint::TARGET_BLOCK_TIME))),
          );
        }
      }
    }
  }
}
