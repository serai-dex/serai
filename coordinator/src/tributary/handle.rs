use core::{ops::Deref, future::Future};
use std::collections::HashMap;

use rand_core::OsRng;

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::dkg::Participant;

use scale::{Encode, Decode};
use serai_client::{
  Public, SeraiAddress, Signature,
  validator_sets::primitives::{ValidatorSet, KeyPair},
  SeraiValidatorSets,
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
    SignData, Transaction, TributarySpec, SeraiBlockNumber, Topic, Label, DataSpecification,
    DataSet, Accumulation,
    signing_protocol::{DkgConfirmer, DkgRemoval},
    scanner::{RecognizedIdType, RIDTrait, PstTxType, TributaryBlockHandler},
    FatallySlashed, DkgShare, DkgCompleted, PlanIds, ConfirmationNonces, RemovalNonces, AttemptDb,
    DataReceived, DataDb,
  },
  P2p,
};

use super::CurrentlyCompletingKeyPair;

pub fn dkg_confirmation_nonces(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  txn: &mut impl DbTxn,
  attempt: u32,
) -> [u8; 64] {
  (DkgConfirmer { key, spec, txn, attempt }).preprocess()
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
  match (DkgConfirmer { key, spec, txn, attempt }).share(preprocesses, &key_pair) {
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
  CurrentlyCompletingKeyPair::set(txn, spec.genesis(), key_pair);
  let preprocesses = ConfirmationNonces::get(txn, spec.genesis(), attempt).unwrap();
  (DkgConfirmer { key, spec, txn, attempt }).share(preprocesses, key_pair)
}

fn unflatten(spec: &TributarySpec, data: &mut HashMap<Participant, Vec<u8>>) {
  for (validator, _) in spec.validators() {
    let range = spec.i(validator).unwrap();
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
    T: DbTxn,
    Pro: Processors,
    FPst: Future<Output = ()>,
    PST: Fn(ValidatorSet, PstTxType, serai_client::Transaction) -> FPst,
    FPtt: Future<Output = ()>,
    PTT: Fn(Transaction) -> FPtt,
    FRid: Future<Output = ()>,
    RID: RIDTrait<FRid>,
    P: P2p,
  > TributaryBlockHandler<'_, T, Pro, FPst, PST, FPtt, PTT, FRid, RID, P>
{
  fn accumulate(
    &mut self,
    data_spec: &DataSpecification,
    signer: <Ristretto as Ciphersuite>::G,
    data: &Vec<u8>,
  ) -> Accumulation {
    let genesis = self.spec.genesis();
    if DataDb::get(self.txn, genesis, data_spec, &signer.to_bytes()).is_some() {
      panic!("accumulating data for a participant multiple times");
    }
    let signer_shares = {
      let signer_i =
        self.spec.i(signer).expect("transaction signed by a non-validator for this tributary");
      u16::from(signer_i.end) - u16::from(signer_i.start)
    };

    let prior_received = DataReceived::get(self.txn, genesis, data_spec).unwrap_or_default();
    let now_received = prior_received + signer_shares;
    DataReceived::set(self.txn, genesis, data_spec, &now_received);
    DataDb::set(self.txn, genesis, data_spec, &signer.to_bytes(), data);

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    let needed = if (data_spec.topic == Topic::Dkg) || (data_spec.topic == Topic::DkgConfirmation) {
      self.spec.n()
    } else {
      self.spec.t()
    };
    if (prior_received < needed) && (now_received >= needed) {
      return Accumulation::Ready({
        let mut data = HashMap::new();
        for validator in self.spec.validators().iter().map(|validator| validator.0) {
          data.insert(
            self.spec.i(validator).unwrap().start,
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
              .i(Ristretto::generator() * self.our_key.deref())
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
    self.accumulate(data_spec, signed.signer, &bytes)
  }

  async fn check_sign_data_len(
    &mut self,
    signer: <Ristretto as Ciphersuite>::G,
    len: usize,
  ) -> Result<(), ()> {
    let signer_i = self.spec.i(signer).unwrap();
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
      Transaction::RemoveParticipant(i) => {
        self.fatal_slash_with_participant_index(i, "RemoveParticipant Provided TX").await
      }

      Transaction::DkgCommitments(attempt, commitments, signed) => {
        let Ok(_) = self.check_sign_data_len(signed.signer, commitments.len()).await else {
          return;
        };
        match self
          .handle_data(
            &DataSpecification { topic: Topic::Dkg, label: Label::Preprocess, attempt },
            commitments.encode(),
            &signed,
          )
          .await
        {
          Accumulation::Ready(DataSet::Participating(mut commitments)) => {
            log::info!("got all DkgCommitments for {}", hex::encode(genesis));
            unflatten(self.spec, &mut commitments);
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
        let Ok(_) = self.check_sign_data_len(signed.signer, shares.len()).await else {
          return;
        };

        let sender_i = self
          .spec
          .i(signed.signer)
          .expect("transaction added to tributary by signer who isn't a participant");
        let sender_is_len = u16::from(sender_i.end) - u16::from(sender_i.start);
        for shares in &shares {
          if shares.len() != (usize::from(self.spec.n() - sender_is_len)) {
            self.fatal_slash(signed.signer.to_bytes(), "invalid amount of DKG shares").await;
            return;
          }
        }

        // Save each share as needed for blame
        {
          let from_range = self.spec.i(signed.signer).unwrap();
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
          .i(Ristretto::generator() * self.our_key.deref())
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

        match self
          .handle_data(
            &DataSpecification { topic: Topic::Dkg, label: Label::Share, attempt },
            (confirmation_nonces.to_vec(), our_shares.encode()).encode(),
            &signed,
          )
          .await
        {
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
        let range = self.spec.i(signed.signer).unwrap();
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

        let share = DkgShare::get(self.txn, genesis, accuser.into(), faulty.into()).unwrap();
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

      Transaction::DkgConfirmed(attempt, shares, signed) => {
        match self
          .handle_data(
            &DataSpecification { topic: Topic::DkgConfirmation, label: Label::Share, attempt },
            shares.to_vec(),
            &signed,
          )
          .await
        {
          Accumulation::Ready(DataSet::Participating(shares)) => {
            log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

            let preprocesses = ConfirmationNonces::get(self.txn, genesis, attempt).unwrap();
            // TODO: This can technically happen under very very very specific timing as the txn put
            // happens before DkgConfirmed, yet the txn commit isn't guaranteed to
            let key_pair = CurrentlyCompletingKeyPair::get(self.txn, genesis).expect(
              "in DkgConfirmed handling, which happens after everyone \
              (including us) fires DkgConfirmed, yet no confirming key pair",
            );
            let sig =
              match (DkgConfirmer { spec: self.spec, key: self.our_key, txn: self.txn, attempt })
                .complete(preprocesses, &key_pair, shares)
              {
                Ok(sig) => sig,
                Err(p) => {
                  self.fatal_slash_with_participant_index(p, "invalid DkgConfirmer share").await;
                  return;
                }
              };

            DkgCompleted::set(self.txn, genesis, &());

            (self.publish_serai_tx)(
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

        let Accumulation::Ready(DataSet::Participating(results)) = self
          .handle_data(
            &DataSpecification {
              topic: Topic::DkgRemoval(data.plan),
              label: data.label,
              attempt: data.attempt,
            },
            data.data.encode(),
            &data.signed,
          )
          .await
        else {
          return;
        };

        match data.label {
          Label::Preprocess => {
            RemovalNonces::set(self.txn, genesis, data.plan, data.attempt, &results);

            let Ok(share) = (DkgRemoval {
              spec: self.spec,
              key: self.our_key,
              txn: self.txn,
              removing: data.plan,
              attempt: data.attempt,
            })
            .share(results) else {
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
            (self.publish_tributary_tx)(tx).await;
          }
          Label::Share => {
            let preprocesses =
              RemovalNonces::get(self.txn, genesis, data.plan, data.attempt).unwrap();

            let Ok((signers, signature)) = (DkgRemoval {
              spec: self.spec,
              key: self.our_key,
              txn: self.txn,
              removing: data.plan,
              attempt: data.attempt,
            })
            .complete(preprocesses, results) else {
              // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
              // slash) and censor transactions (yet don't explicitly ban)
              return;
            };

            // TODO: Only handle this if we're not actively removing any of the signers
            // The created Substrate call will fail if a removed validator was one of the signers
            // Since:
            // 1) publish_serai_tx will block this task until the TX is published
            // 2) We won't scan any more TXs/blocks until we handle this TX
            // The TX *must* be successfully published *before* we start removing any more
            // signers
            // Accordingly, if the signers aren't currently being removed, they won't be removed
            // by the time this transaction is successfully published *unless* a malicious 34%
            // participates with the non-participating 33% to continue operation and produce a
            // distinct removal (since the non-participating won't block in this block)
            // This breaks BFT and is accordingly within bounds

            let tx = serai_client::SeraiValidatorSets::remove_participant(
              self.spec.set().network,
              SeraiAddress(data.plan),
              signers,
              Signature(signature),
            );
            (self.publish_serai_tx)(self.spec.set(), PstTxType::RemoveParticipant(data.plan), tx)
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
        self
          .processors
          .send(
            self.spec.set().network,
            coordinator::CoordinatorMessage::CosignSubstrateBlock {
              id: SubstrateSignId {
                session: self.spec.set().session,
                id: SubstrateSignableId::CosigningSubstrateBlock(hash),
                attempt: 0,
              },
              block_number,
            },
          )
          .await;
      }

      Transaction::Batch(_, batch) => {
        // Because this Batch has achieved synchrony, its batch ID should be authorized
        AttemptDb::recognize_topic(
          self.txn,
          genesis,
          Topic::SubstrateSign(SubstrateSignableId::Batch(batch)),
        );
        (self.recognized_id)(self.spec.set(), genesis, RecognizedIdType::Batch, batch.to_vec())
          .await;
      }

      Transaction::SubstrateBlock(block) => {
        let plan_ids = PlanIds::get(self.txn, &genesis, block).expect(
          "synced a tributary block finalizing a substrate block in a provided transaction \
          despite us not providing that transaction",
        );

        for id in plan_ids.into_iter() {
          AttemptDb::recognize_topic(self.txn, genesis, Topic::Sign(id));
          (self.recognized_id)(self.spec.set(), genesis, RecognizedIdType::Plan, id.to_vec()).await;
        }
      }

      Transaction::SubstrateSign(data) => {
        let signer = data.signed.signer;
        let Ok(_) = self.check_sign_data_len(signer, data.data.len()).await else {
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
          }
        }

        if let Accumulation::Ready(DataSet::Participating(mut results)) = self
          .handle_data(
            &DataSpecification {
              topic: Topic::SubstrateSign(data.plan),
              label: data.label,
              attempt: data.attempt,
            },
            data.data.encode(),
            &data.signed,
          )
          .await
        {
          unflatten(self.spec, &mut results);
          let id = SubstrateSignId {
            session: self.spec.set().session,
            id: data.plan,
            attempt: data.attempt,
          };
          self
            .processors
            .send(
              self.spec.set().network,
              match data.label {
                Label::Preprocess => coordinator::CoordinatorMessage::SubstratePreprocesses {
                  id,
                  preprocesses: results
                    .into_iter()
                    .map(|(v, p)| (v, p.try_into().unwrap()))
                    .collect(),
                },
                Label::Share => coordinator::CoordinatorMessage::SubstrateShares {
                  id,
                  shares: results.into_iter().map(|(v, p)| (v, p.try_into().unwrap())).collect(),
                },
              },
            )
            .await;
        }
      }

      Transaction::Sign(data) => {
        let Ok(_) = self.check_sign_data_len(data.signed.signer, data.data.len()).await else {
          return;
        };
        if let Accumulation::Ready(DataSet::Participating(mut results)) = self
          .handle_data(
            &DataSpecification {
              topic: Topic::Sign(data.plan),
              label: data.label,
              attempt: data.attempt,
            },
            data.data.encode(),
            &data.signed,
          )
          .await
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
          self
            .fatal_slash(first_signer.to_bytes(), "claimed an unrecognized plan was completed")
            .await;
          return;
        };

        // TODO: Confirm this signer hasn't prior published a completion

        self
          .processors
          .send(
            self.spec.set().network,
            sign::CoordinatorMessage::Completed {
              session: self.spec.set().session,
              id: plan,
              tx: tx_hash,
            },
          )
          .await;
      }
    }
  }
}
