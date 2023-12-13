use core::ops::Deref;
use std::collections::HashMap;

use rand_core::OsRng;

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::dkg::Participant;

use scale::{Encode, Decode};
use serai_client::{
  Public, SeraiAddress, Signature, validator_sets::primitives::KeyPair, SeraiValidatorSets,
};

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
    signing_protocol::{DkgConfirmer, DkgRemoval},
    scanner::{RecognizedIdType, RIDTrait, PstTxType, PSTTrait, PTTTrait, TributaryBlockHandler},
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

// If there's an error generating a key pair, return any errors which would've occured when
// executing the DkgConfirmer in order to stay in sync with those who did.
//
// The caller must ensure only error_generating_key_pair or generated_key_pair is called for a
// given attempt.
pub fn error_generating_key_pair(
  txn: &mut impl DbTxn,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  attempt: u32,
) -> Option<Participant> {
  let preprocesses = ConfirmationNonces::get(txn, spec.genesis(), attempt).unwrap();

  // Sign a key pair which can't be valid
  // (0xff used as 0 would be the Ristretto identity point, 0-length for the network key)
  let key_pair = KeyPair(Public([0xff; 32]), vec![0xffu8; 0].try_into().unwrap());
  match DkgConfirmer::new(key, spec, txn, attempt)
    .expect("reporting an error during DKG for an unrecognized attempt")
    .share(preprocesses, &key_pair)
  {
    Ok(mut share) => {
      // Zeroize the share to ensure it's not accessed
      share.zeroize();
      None
    }
    Err(p) => Some(p),
  }
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
    let range = spec.i(removed, validator).unwrap();
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

impl<T: DbTxn, Pro: Processors, PST: PSTTrait, PTT: PTTTrait, RID: RIDTrait, P: P2p>
  TributaryBlockHandler<'_, T, Pro, PST, PTT, RID, P>
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
      let signer_i = self
        .spec
        .i(removed, signer)
        .expect("transaction signed by a non-validator for this tributary");
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

      // Because this attempt was participated in, it was justified
      // The question becomes why did the prior attempt fail?
      // TODO: Slash people who failed to participate as expected in the prior attempt
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
      return Accumulation::Ready({
        let mut data = HashMap::new();
        for validator in self.spec.validators().iter().map(|validator| validator.0) {
          data.insert(
            self.spec.i(removed, validator).unwrap().start,
            if let Some(data) = DataDb::get(self.txn, genesis, data_spec, &validator.to_bytes()) {
              data
            } else {
              continue;
            },
          );
        }

        assert_eq!(data.len(), usize::from(needed));

        // Remove our own piece of data, if we were involved
        if data
          .remove(
            &self
              .spec
              .i(removed, Ristretto::generator() * self.our_key.deref())
              .expect("handling a message for a Tributary we aren't part of")
              .start,
          )
          .is_some()
        {
          DataSet::Participating(data)
        } else {
          DataSet::NotParticipating
        }
      });
    }
    Accumulation::NotReady
  }

  async fn handle_data(
    &mut self,
    removed: &[<Ristretto as Ciphersuite>::G],
    data_spec: &DataSpecification,
    bytes: Vec<u8>,
    signed: &Signed,
  ) -> Accumulation {
    let genesis = self.spec.genesis();

    let Some(curr_attempt) = AttemptDb::attempt(self.txn, genesis, data_spec.topic) else {
      // Premature publication of a valid ID/publication of an invalid ID
      self.fatal_slash(signed.signer.to_bytes(), "published data for ID without an attempt").await;
      return Accumulation::NotReady;
    };

    // If they've already published a TX for this attempt, slash
    // This shouldn't be reachable since nonces were made inserted by the coordinator, yet it's a
    // cheap check to leave in for safety
    if DataDb::get(self.txn, genesis, data_spec, &signed.signer.to_bytes()).is_some() {
      self.fatal_slash(signed.signer.to_bytes(), "published data multiple times").await;
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
      self
        .fatal_slash(
          signed.signer.to_bytes(),
          "published data with an attempt which hasn't started",
        )
        .await;
      return Accumulation::NotReady;
    }

    // TODO: We can also full slash if shares before all commitments, or share before the
    // necessary preprocesses

    // TODO: If this is shares, we need to check they are part of the selected signing set

    // Accumulate this data
    self.accumulate(removed, data_spec, signed.signer, &bytes)
  }

  async fn check_sign_data_len(
    &mut self,
    removed: &[<Ristretto as Ciphersuite>::G],
    signer: <Ristretto as Ciphersuite>::G,
    len: usize,
  ) -> Result<(), ()> {
    let signer_i = self.spec.i(removed, signer).unwrap();
    if len != usize::from(u16::from(signer_i.end) - u16::from(signer_i.start)) {
      self
        .fatal_slash(
          signer.to_bytes(),
          "signer published a distinct amount of sign data than they had shares",
        )
        .await;
      Err(())?;
    }
    Ok(())
  }

  fn dkg_removal<'a>(
    &'a mut self,
    removed: &'a [<Ristretto as Ciphersuite>::G],
    data: &'a SignData<[u8; 32]>,
  ) -> DkgRemoval<'a, T> {
    DkgRemoval {
      key: self.our_key,
      spec: self.spec,
      txn: self.txn,
      removed,
      removing: data.plan,
      attempt: data.attempt,
    }
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
      Transaction::RemoveParticipantDueToDkg { attempt, participant } => {
        self
          .fatal_slash_with_participant_index(
            &removed_as_of_dkg_attempt(self.txn, genesis, attempt).unwrap_or_else(|| {
              panic!(
                "removed a participant due to a provided transaction with an attempt not {}",
                "locally handled?"
              )
            }),
            participant,
            "RemoveParticipantDueToDkg Provided TX",
          )
          .await
      }

      Transaction::DkgCommitments { attempt, commitments, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self
            .fatal_slash(signed.signer.to_bytes(), "DkgCommitments with an unrecognized attempt")
            .await;
          return;
        };
        let Ok(_) = self.check_sign_data_len(&removed, signed.signer, commitments.len()).await
        else {
          return;
        };
        let data_spec = DataSpecification { topic: Topic::Dkg, label: Label::Preprocess, attempt };
        match self.handle_data(&removed, &data_spec, commitments.encode(), &signed).await {
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
            panic!("wasn't a participant in DKG commitments")
          }
          Accumulation::NotReady => {}
        }
      }

      Transaction::DkgShares { attempt, mut shares, confirmation_nonces, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self
            .fatal_slash(signed.signer.to_bytes(), "DkgShares with an unrecognized attempt")
            .await;
          return;
        };
        let Ok(_) = self.check_sign_data_len(&removed, signed.signer, shares.len()).await else {
          return;
        };

        let sender_i = self
          .spec
          .i(&removed, signed.signer)
          .expect("transaction added to tributary by signer who isn't a participant");
        let sender_is_len = u16::from(sender_i.end) - u16::from(sender_i.start);
        for shares in &shares {
          if shares.len() != (usize::from(self.spec.n(&removed) - sender_is_len)) {
            self.fatal_slash(signed.signer.to_bytes(), "invalid amount of DKG shares").await;
            return;
          }
        }

        // Save each share as needed for blame
        {
          let from_range = self.spec.i(&removed, signed.signer).unwrap();
          for (from_offset, shares) in shares.iter().enumerate() {
            let from =
              Participant::new(u16::from(from_range.start) + u16::try_from(from_offset).unwrap())
                .unwrap();

            for (to_offset, share) in shares.iter().enumerate() {
              // 0-indexed (the enumeration) to 1-indexed (Participant)
              let mut to = u16::try_from(to_offset).unwrap() + 1;
              // Adjust for the omission of the sender's own shares
              if to >= u16::from(from_range.start) {
                to += u16::from(from_range.end) - u16::from(from_range.start);
              }
              let to = Participant::new(to).unwrap();

              DkgShare::set(self.txn, genesis, from.into(), to.into(), share);
            }
          }
        }

        // Filter down to only our share's bytes for handle
        let our_i = self
          .spec
          .i(&removed, Ristretto::generator() * self.our_key.deref())
          .expect("in a tributary we're not a validator for");

        let our_shares = if sender_i == our_i {
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
        };
        // Drop shares as it's been mutated into invalidity
        drop(shares);

        let data_spec = DataSpecification { topic: Topic::Dkg, label: Label::Share, attempt };
        let encoded_data = (confirmation_nonces.to_vec(), our_shares.encode()).encode();
        match self.handle_data(&removed, &data_spec, encoded_data, &signed).await {
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
            panic!("wasn't a participant in DKG shares")
          }
          Accumulation::NotReady => {}
        }
      }

      Transaction::InvalidDkgShare { attempt, accuser, faulty, blame, signed } => {
        let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
          self
            .fatal_slash(signed.signer.to_bytes(), "InvalidDkgShare with an unrecognized attempt")
            .await;
          return;
        };
        let range = self.spec.i(&removed, signed.signer).unwrap();
        if !range.contains(&accuser) {
          self
            .fatal_slash(
              signed.signer.to_bytes(),
              "accused with a Participant index which wasn't theirs",
            )
            .await;
          return;
        }
        if range.contains(&faulty) {
          self
            .fatal_slash(signed.signer.to_bytes(), "accused self of having an InvalidDkgShare")
            .await;
          return;
        }

        let Some(share) = DkgShare::get(self.txn, genesis, accuser.into(), faulty.into()) else {
          self
            .fatal_slash(
              signed.signer.to_bytes(),
              "InvalidDkgShare had a non-existent faulty participant",
            )
            .await;
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
          self
            .fatal_slash(signed.signer.to_bytes(), "DkgConfirmed with an unrecognized attempt")
            .await;
          return;
        };

        let data_spec =
          DataSpecification { topic: Topic::DkgConfirmation, label: Label::Share, attempt };
        match self.handle_data(&removed, &data_spec, confirmation_share.to_vec(), &signed).await {
          Accumulation::Ready(DataSet::Participating(shares)) => {
            log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

            let Some(removed) = removed_as_of_dkg_attempt(self.txn, genesis, attempt) else {
              panic!(
                "DkgConfirmed for everyone yet didn't have the removed parties for this attempt",
              );
            };

            let preprocesses = ConfirmationNonces::get(self.txn, genesis, attempt).unwrap();
            // TODO: This can technically happen under very very very specific timing as the txn put
            // happens before DkgConfirmed, yet the txn commit isn't guaranteed to
            let key_pair = DkgKeyPair::get(self.txn, genesis, attempt).expect(
              "in DkgConfirmed handling, which happens after everyone \
              (including us) fires DkgConfirmed, yet no confirming key pair",
            );
            let mut confirmer = DkgConfirmer::new(self.our_key, self.spec, self.txn, attempt)
              .expect("confirming DKG for unrecognized attempt");
            let sig = match confirmer.complete(preprocesses, &key_pair, shares) {
              Ok(sig) => sig,
              Err(p) => {
                self
                  .fatal_slash_with_participant_index(&removed, p, "invalid DkgConfirmer share")
                  .await;
                return;
              }
            };

            DkgCompleted::set(self.txn, genesis, &());

            self
              .publish_serai_tx
              .publish_serai_tx(
                self.spec.set(),
                PstTxType::SetKeys,
                SeraiValidatorSets::set_keys(self.spec.set().network, key_pair, Signature(sig)),
              )
              .await;
          }
          Accumulation::Ready(DataSet::NotParticipating) => {
            panic!("wasn't a participant in DKG confirmination shares")
          }
          Accumulation::NotReady => {}
        }
      }

      Transaction::DkgRemoval(data) => {
        let signer = data.signed.signer;
        let expected_len = match data.label {
          Label::Preprocess => 64,
          Label::Share => 32,
        };
        if (data.data.len() != 1) || (data.data[0].len() != expected_len) {
          self.fatal_slash(signer.to_bytes(), "unexpected length data for dkg removal").await;
          return;
        }

        let Some(removed) =
          crate::tributary::removed_as_of_fatal_slash(self.txn, genesis, data.plan)
        else {
          self.fatal_slash(signer.to_bytes(), "removing someone who wasn't fatally slashed").await;
          return;
        };

        let data_spec = DataSpecification {
          topic: Topic::DkgRemoval(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        let Accumulation::Ready(DataSet::Participating(results)) =
          self.handle_data(&removed, &data_spec, data.data.encode(), &data.signed).await
        else {
          return;
        };

        match data.label {
          Label::Preprocess => {
            RemovalNonces::set(self.txn, genesis, data.plan, data.attempt, &results);

            let Ok(share) = self.dkg_removal(&removed, &data).share(results) else {
              // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
              // slash) and censor transactions (yet don't explicitly ban)
              return;
            };

            let mut tx = Transaction::DkgRemoval(SignData {
              plan: data.plan,
              attempt: data.attempt,
              label: Label::Preprocess,
              data: vec![share.to_vec()],
              signed: Transaction::empty_signed(),
            });
            tx.sign(&mut OsRng, genesis, self.our_key);
            self.publish_tributary_tx.publish_tributary_tx(tx).await;
          }
          Label::Share => {
            let preprocesses =
              RemovalNonces::get(self.txn, genesis, data.plan, data.attempt).unwrap();

            let Ok((signers, signature)) =
              self.dkg_removal(&removed, &data).complete(preprocesses, results)
            else {
              // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
              // slash) and censor transactions (yet don't explicitly ban)
              return;
            };

            // We need to only handle this if we're not actively removing any of the signers
            // At the start of this function, we only handle messages from non-fatally slashed
            // participants, so this is held
            //
            // The created Substrate call will fail if a removed validator was one of the signers
            // Since:
            // 1) publish_serai_tx will block this task until the TX is published
            // 2) We won't scan any more TXs/blocks until we handle this TX
            // The TX *must* be successfully published *before* we start removing any more
            // signers
            //
            // Accordingly, if the signers aren't currently being removed, they won't be removed
            // by the time this transaction is successfully published *unless* a malicious 34%
            // participates with the non-participating 33% to continue operation and produce a
            // distinct removal (since the non-participating won't block in this block)
            //
            // This breaks BFT and is accordingly within bounds

            let tx = serai_client::SeraiValidatorSets::remove_participant(
              self.spec.set().network,
              SeraiAddress(data.plan),
              signers,
              Signature(signature),
            );
            LocallyDkgRemoved::set(self.txn, genesis, data.plan, &());
            self
              .publish_serai_tx
              .publish_serai_tx(self.spec.set(), PstTxType::RemoveParticipant(data.plan), tx)
              .await;
          }
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

        for id in plan_ids.into_iter() {
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
          self
            .fatal_slash(
              data.signed.signer.to_bytes(),
              "signing despite not having set keys on substrate",
            )
            .await;
          return;
        };
        let signer = data.signed.signer;
        let Ok(_) = self.check_sign_data_len(&removed, signer, data.data.len()).await else {
          return;
        };
        let expected_len = match data.label {
          Label::Preprocess => 64,
          Label::Share => 32,
        };
        for data in &data.data {
          if data.len() != expected_len {
            self
              .fatal_slash(
                signer.to_bytes(),
                "unexpected length data for substrate signing protocol",
              )
              .await;
            return;
          }
        }

        let data_spec = DataSpecification {
          topic: Topic::SubstrateSign(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        let Accumulation::Ready(DataSet::Participating(mut results)) =
          self.handle_data(&removed, &data_spec, data.data.encode(), &data.signed).await
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
          self
            .fatal_slash(
              data.signed.signer.to_bytes(),
              "signing despite not having set keys on substrate",
            )
            .await;
          return;
        };
        let Ok(_) = self.check_sign_data_len(&removed, data.signed.signer, data.data.len()).await
        else {
          return;
        };

        let data_spec = DataSpecification {
          topic: Topic::Sign(data.plan),
          label: data.label,
          attempt: data.attempt,
        };
        if let Accumulation::Ready(DataSet::Participating(mut results)) =
          self.handle_data(&removed, &data_spec, data.data.encode(), &data.signed).await
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
          self
            .fatal_slash(first_signer.to_bytes(), "claimed an unrecognized plan was completed")
            .await;
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
