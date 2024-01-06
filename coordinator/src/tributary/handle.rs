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
  key_gen::{self, KeyGenId},
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
  DkgConfirmer::new(key, spec, txn, attempt)
    .expect("getting DKG confirmation nonces for unknown attempt")
    .preprocess()
}

pub fn generated_key_pair<D: Db>(
  txn: &mut D::Transaction<'_>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  key_pair: &KeyPair,
  attempt: u32,
) -> Result<[u8; 32], Participant> {
  DkgKeyPair::set(txn, spec.genesis(), attempt, key_pair);
  KeyToDkgAttempt::set(txn, key_pair.0 .0, &attempt);
  let preprocesses = ConfirmationNonces::get(txn, spec.genesis(), attempt).unwrap();
  DkgConfirmer::new(key, spec, txn, attempt)
    .expect("claiming to have generated a key pair for an unrecognized attempt")
    .share(preprocesses, key_pair)
}

fn unflatten(
  spec: &TributarySpec,
  removed: &[<Ristretto as Ciphersuite>::G],
  data: &mut HashMap<Participant, Vec<u8>>,
) {
  for (validator, _) in spec.validators() {
    let Some(range) = spec.i(removed, validator) else { continue };
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
    removed: &[<Ristretto as Ciphersuite>::G],
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
      let Some(signer_i) = self.spec.i(removed, signer) else {
        log::warn!("accumulating data from {} who was removed", hex::encode(signer.to_bytes()));
        return Accumulation::NotReady;
      };
      u16::from(signer_i.end) - u16::from(signer_i.start)
    };

    let prior_received = DataReceived::get(self.txn, genesis, data_spec).unwrap_or_default();
    let now_received = prior_received + signer_shares;
    DataReceived::set(self.txn, genesis, data_spec, &now_received);
    DataDb::set(self.txn, genesis, data_spec, &signer.to_bytes(), data);

    let received_range = (prior_received + 1) ..= now_received;

    // If 2/3rds of the network participated in this preprocess, queue it for an automatic
    // re-attempt
    // DkgConfirmation doesn't have a re-attempt as it's just an extension for Dkg
    if (data_spec.label == Label::Preprocess) &&
      received_range.contains(&self.spec.t()) &&
      (data_spec.topic != Topic::DkgConfirmation)
    {
      // Double check the attempt on this entry, as we don't want to schedule a re-attempt if this
      // is an old entry
      // This is an assert, not part of the if check, as old data shouldn't be here in the first
      // place
      assert_eq!(AttemptDb::attempt(self.txn, genesis, data_spec.topic), Some(data_spec.attempt));
      ReattemptDb::schedule_reattempt(self.txn, genesis, self.block_number, data_spec.topic);
    }

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    let needs_everyone =
      (data_spec.topic == Topic::Dkg) || (data_spec.topic == Topic::DkgConfirmation);
    let needed = if needs_everyone { self.spec.n(removed) } else { self.spec.t() };
    if received_range.contains(&needed) {
      log::debug!(
        "accumulation for entry {:?} attempt #{} is ready",
        &data_spec.topic,
        &data_spec.attempt
      );

      let mut data = HashMap::new();
      for validator in self.spec.validators().iter().map(|validator| validator.0) {
        let Some(i) = self.spec.i(removed, validator) else { continue };
        data.insert(
          i.start,
          if let Some(data) = DataDb::get(self.txn, genesis, data_spec, &validator.to_bytes()) {
            data
          } else {
            continue;
          },
        );
      }

      assert_eq!(data.len(), usize::from(needed));

      // Remove our own piece of data, if we were involved
      if let Some(i) = self.spec.i(removed, Ristretto::generator() * self.our_key.deref()) {
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
    removed: &[<Ristretto as Ciphersuite>::G],
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
    self.accumulate(removed, data_spec, signed.signer, bytes)
  }

  fn check_sign_data_len(
    &mut self,
    removed: &[<Ristretto as Ciphersuite>::G],
    signer: <Ristretto as Ciphersuite>::G,
    len: usize,
  ) -> Result<(), ()> {
    let Some(signer_i) = self.spec.i(removed, signer) else {
      // TODO: Ensure processor doesn't so participate/check how it handles removals for being
      // offline
      self.fatal_slash(signer.to_bytes(), "signer participated despite being removed");
      Err(())?
    };
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
      Transaction::RemoveParticipantDueToDkg { participant, signed } => {
        if self.spec.i(&[], participant).is_none() {
          self.fatal_slash(
            participant.to_bytes(),
            "RemoveParticipantDueToDkg vote for non-validator",
          );
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
          self.spec.i(&[], signed.signer).expect("signer wasn't a validator for this network?");
        let new_votes = prior_votes + u16::from(signer_votes.end) - u16::from(signer_votes.start);
        VotesToRemove::set(self.txn, genesis, participant, &new_votes);
        if ((prior_votes + 1) ..= new_votes).contains(&self.spec.t()) {
          self.fatal_slash(participant, "RemoveParticipantDueToDkg vote")
        }
      }

      Transaction::DkgCommitments { attempt, commitments, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self.fatal_slash(signed.signer.to_bytes(), "DkgCommitments with an unrecognized attempt");
          return;
        };
        let Ok(()) = self.check_sign_data_len(&removed, signed.signer, commitments.len()) else {
          return;
        };
        let data_spec = DataSpecification { topic: Topic::Dkg, label: Label::Preprocess, attempt };
        match self.handle_data(&removed, &data_spec, &commitments.encode(), &signed) {
          Accumulation::Ready(DataSet::Participating(mut commitments)) => {
            log::info!("got all DkgCommitments for {}", hex::encode(genesis));
            unflatten(self.spec, &removed, &mut commitments);
            self
              .processors
              .send(
                self.spec.set().network,
                key_gen::CoordinatorMessage::Commitments {
                  id: KeyGenId { session: self.spec.set().session, attempt },
                  commitments,
                },
              )
              .await;
          }
          Accumulation::Ready(DataSet::NotParticipating) => {
            assert!(
              removed.contains(&(Ristretto::generator() * self.our_key.deref())),
              "NotParticipating in a DkgCommitments we weren't removed for"
            );
          }
          Accumulation::NotReady => {}
        }
      }

      Transaction::DkgShares { attempt, mut shares, confirmation_nonces, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self.fatal_slash(signed.signer.to_bytes(), "DkgShares with an unrecognized attempt");
          return;
        };
        let not_participating = removed.contains(&(Ristretto::generator() * self.our_key.deref()));

        let Ok(()) = self.check_sign_data_len(&removed, signed.signer, shares.len()) else {
          return;
        };

        let Some(sender_i) = self.spec.i(&removed, signed.signer) else {
          self.fatal_slash(
            signed.signer.to_bytes(),
            "DkgShares for a DKG they aren't participating in",
          );
          return;
        };
        let sender_is_len = u16::from(sender_i.end) - u16::from(sender_i.start);
        for shares in &shares {
          if shares.len() != (usize::from(self.spec.n(&removed) - sender_is_len)) {
            self.fatal_slash(signed.signer.to_bytes(), "invalid amount of DKG shares");
            return;
          }
        }

        // Save each share as needed for blame
        for (from_offset, shares) in shares.iter().enumerate() {
          let from =
            Participant::new(u16::from(sender_i.start) + u16::try_from(from_offset).unwrap())
              .unwrap();

          for (to_offset, share) in shares.iter().enumerate() {
            // 0-indexed (the enumeration) to 1-indexed (Participant)
            let mut to = u16::try_from(to_offset).unwrap() + 1;
            // Adjust for the omission of the sender's own shares
            if to >= u16::from(sender_i.start) {
              to += u16::from(sender_i.end) - u16::from(sender_i.start);
            }
            let to = Participant::new(to).unwrap();

            DkgShare::set(self.txn, genesis, from.into(), to.into(), share);
          }
        }

        // Filter down to only our share's bytes for handle
        let our_shares = if let Some(our_i) =
          self.spec.i(&removed, Ristretto::generator() * self.our_key.deref())
        {
          if sender_i == our_i {
            vec![]
          } else {
            // 1-indexed to 0-indexed
            let mut our_i_pos = u16::from(our_i.start) - 1;
            // Handle the omission of the sender's own data
            if u16::from(our_i.start) > u16::from(sender_i.start) {
              our_i_pos -= sender_is_len;
            }
            let our_i_pos = usize::from(our_i_pos);
            shares
              .iter_mut()
              .map(|shares| {
                shares
                  .drain(
                    our_i_pos ..
                      (our_i_pos + usize::from(u16::from(our_i.end) - u16::from(our_i.start))),
                  )
                  .collect::<Vec<_>>()
              })
              .collect()
          }
        } else {
          assert!(
            not_participating,
            "we didn't have an i while handling DkgShares we weren't removed for"
          );
          // Since we're not participating, simply save vec![] for our shares
          vec![]
        };
        // Drop shares as it's presumably been mutated into invalidity
        drop(shares);

        let data_spec = DataSpecification { topic: Topic::Dkg, label: Label::Share, attempt };
        let encoded_data = (confirmation_nonces.to_vec(), our_shares.encode()).encode();
        match self.handle_data(&removed, &data_spec, &encoded_data, &signed) {
          Accumulation::Ready(DataSet::Participating(confirmation_nonces_and_shares)) => {
            log::info!("got all DkgShares for {}", hex::encode(genesis));

            let mut confirmation_nonces = HashMap::new();
            let mut shares = HashMap::new();
            for (participant, confirmation_nonces_and_shares) in confirmation_nonces_and_shares {
              let (these_confirmation_nonces, these_shares) =
                <(Vec<u8>, Vec<u8>)>::decode(&mut confirmation_nonces_and_shares.as_slice())
                  .unwrap();
              confirmation_nonces.insert(participant, these_confirmation_nonces);
              shares.insert(participant, these_shares);
            }
            ConfirmationNonces::set(self.txn, genesis, attempt, &confirmation_nonces);

            // shares is a HashMap<Participant, Vec<Vec<Vec<u8>>>>, with the values representing:
            // - Each of the sender's shares
            // - Each of the our shares
            // - Each share
            // We need a Vec<HashMap<Participant, Vec<u8>>>, with the outer being each of ours
            let mut expanded_shares = vec![];
            for (sender_start_i, shares) in shares {
              let shares: Vec<Vec<Vec<u8>>> = Vec::<_>::decode(&mut shares.as_slice()).unwrap();
              for (sender_i_offset, our_shares) in shares.into_iter().enumerate() {
                for (our_share_i, our_share) in our_shares.into_iter().enumerate() {
                  if expanded_shares.len() <= our_share_i {
                    expanded_shares.push(HashMap::new());
                  }
                  expanded_shares[our_share_i].insert(
                    Participant::new(
                      u16::from(sender_start_i) + u16::try_from(sender_i_offset).unwrap(),
                    )
                    .unwrap(),
                    our_share,
                  );
                }
              }
            }

            self
              .processors
              .send(
                self.spec.set().network,
                key_gen::CoordinatorMessage::Shares {
                  id: KeyGenId { session: self.spec.set().session, attempt },
                  shares: expanded_shares,
                },
              )
              .await;
          }
          Accumulation::Ready(DataSet::NotParticipating) => {
            assert!(not_participating, "NotParticipating in a DkgShares we weren't removed for");
          }
          Accumulation::NotReady => {}
        }
      }

      Transaction::InvalidDkgShare { attempt, accuser, faulty, blame, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self
            .fatal_slash(signed.signer.to_bytes(), "InvalidDkgShare with an unrecognized attempt");
          return;
        };
        let Some(range) = self.spec.i(&removed, signed.signer) else {
          self.fatal_slash(
            signed.signer.to_bytes(),
            "InvalidDkgShare for a DKG they aren't participating in",
          );
          return;
        };
        if !range.contains(&accuser) {
          self.fatal_slash(
            signed.signer.to_bytes(),
            "accused with a Participant index which wasn't theirs",
          );
          return;
        }
        if range.contains(&faulty) {
          self.fatal_slash(signed.signer.to_bytes(), "accused self of having an InvalidDkgShare");
          return;
        }

        let Some(share) = DkgShare::get(self.txn, genesis, accuser.into(), faulty.into()) else {
          self.fatal_slash(
            signed.signer.to_bytes(),
            "InvalidDkgShare had a non-existent faulty participant",
          );
          return;
        };
        self
          .processors
          .send(
            self.spec.set().network,
            key_gen::CoordinatorMessage::VerifyBlame {
              id: KeyGenId { session: self.spec.set().session, attempt },
              accuser,
              accused: faulty,
              share,
              blame,
            },
          )
          .await;
      }

      Transaction::DkgConfirmed { attempt, confirmation_share, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self.fatal_slash(signed.signer.to_bytes(), "DkgConfirmed with an unrecognized attempt");
          return;
        };

        let data_spec =
          DataSpecification { topic: Topic::DkgConfirmation, label: Label::Share, attempt };
        match self.handle_data(&removed, &data_spec, &confirmation_share.to_vec(), &signed) {
          Accumulation::Ready(DataSet::Participating(shares)) => {
            log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

            let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
              panic!(
                "DkgConfirmed for everyone yet didn't have the removed parties for this attempt",
              );
            };

            let preprocesses = ConfirmationNonces::get(self.txn, genesis, attempt).unwrap();
            // TODO: This can technically happen under very very very specific timing as the txn
            // put happens before DkgConfirmed, yet the txn commit isn't guaranteed to
            let key_pair = DkgKeyPair::get(self.txn, genesis, attempt).expect(
              "in DkgConfirmed handling, which happens after everyone \
              (including us) fires DkgConfirmed, yet no confirming key pair",
            );
            let mut confirmer = DkgConfirmer::new(self.our_key, self.spec, self.txn, attempt)
              .expect("confirming DKG for unrecognized attempt");
            let sig = match confirmer.complete(preprocesses, &key_pair, shares) {
              Ok(sig) => sig,
              Err(p) => {
                let mut tx = Transaction::RemoveParticipantDueToDkg {
                  participant: self.spec.reverse_lookup_i(&removed, p).unwrap(),
                  signed: Transaction::empty_signed(),
                };
                tx.sign(&mut OsRng, genesis, self.our_key);
                self.publish_tributary_tx.publish_tributary_tx(tx).await;
                return;
              }
            };

            DkgLocallyCompleted::set(self.txn, genesis, &());

            self
              .publish_serai_tx
              .publish_set_keys(
                self.db,
                self.spec.set(),
                removed.into_iter().map(|key| key.to_bytes().into()).collect(),
                key_pair,
                Signature(sig),
              )
              .await;
          }
          Accumulation::Ready(DataSet::NotParticipating) => {
            panic!("wasn't a participant in DKG confirmination shares")
          }
          Accumulation::NotReady => {}
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
        // Provided transactions ensure synchrony on any signing protocol, and we won't start
        // signing with threshold keys before we've confirmed them on-chain
        let Some(removed) =
          crate::tributary::removed_as_of_set_keys(self.txn, self.spec.set(), genesis)
        else {
          self.fatal_slash(
            data.signed.signer.to_bytes(),
            "signing despite not having set keys on substrate",
          );
          return;
        };
        let signer = data.signed.signer;
        let Ok(()) = self.check_sign_data_len(&removed, signer, data.data.len()) else {
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
          self.handle_data(&removed, &data_spec, &data.data.encode(), &data.signed)
        else {
          return;
        };
        unflatten(self.spec, &removed, &mut results);

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
        let Some(removed) =
          crate::tributary::removed_as_of_set_keys(self.txn, self.spec.set(), genesis)
        else {
          self.fatal_slash(
            data.signed.signer.to_bytes(),
            "signing despite not having set keys on substrate",
          );
          return;
        };
        let Ok(()) = self.check_sign_data_len(&removed, data.signed.signer, data.data.len()) else {
          return;
        };

        let data_spec = DataSpecification {
          topic: Topic::Sign(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        if let Accumulation::Ready(DataSet::Participating(mut results)) =
          self.handle_data(&removed, &data_spec, &data.data.encode(), &data.signed)
        {
          unflatten(self.spec, &removed, &mut results);
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
    }
  }
}
