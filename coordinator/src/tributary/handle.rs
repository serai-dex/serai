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
    SignData, Transaction, TributarySpec, SeraiBlockNumber, Topic, DataSpecification, DataSet,
    Accumulation,
    dkg_confirmer::DkgConfirmer,
    dkg_removal::DkgRemoval,
    scanner::{RecognizedIdType, RIDTrait, PstTxType},
    FatallySlashed, DkgShare, DkgCompleted, PlanIds, ConfirmationNonces, RemovalNonces, AttemptDb,
    DataDb,
  },
};

use super::CurrentlyCompletingKeyPair;

const DKG_COMMITMENTS: &str = "commitments";
const DKG_SHARES: &str = "shares";
const DKG_CONFIRMATION_NONCES: &str = "confirmation_nonces";
const DKG_CONFIRMATION_SHARES: &str = "confirmation_shares";

// These d/s/b prefixes between DKG Removal, Batch, and Sign should be unnecessary, as Batch/Share
// entries themselves should already be domain separated
const DKG_REMOVAL_PREPROCESS: &str = "d_preprocess";
const DKG_REMOVAL_SHARE: &str = "d_share";

const BATCH_PREPROCESS: &str = "b_preprocess";
const BATCH_SHARE: &str = "b_share";

const SIGN_PREPROCESS: &str = "s_preprocess";
const SIGN_SHARE: &str = "s_share";

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

pub(super) async fn fatal_slash<D: Db, FPtt: Future<Output = ()>, PTT: Fn(Transaction) -> FPtt>(
  txn: &mut D::Transaction<'_>,
  spec: &TributarySpec,
  publish_tributary_tx: &PTT,
  our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  slashing: [u8; 32],
  reason: &str,
) {
  let genesis = spec.genesis();

  log::warn!("fatally slashing {}. reason: {}", hex::encode(slashing), reason);
  FatallySlashed::set_fatally_slashed(txn, genesis, slashing);
  // TODO: disconnect the node from network/ban from further participation in all Tributaries

  // TODO: If during DKG, trigger a re-attempt
  // Despite triggering a re-attempt, this DKG may still complete and may become in-use

  // If during a DKG, remove the participant
  if DkgCompleted::get(txn, genesis).is_none() {
    let preprocess =
      (DkgRemoval { spec, key: our_key, txn, removing: slashing, attempt: 0 }).preprocess();
    let mut tx = Transaction::DkgRemovalPreprocess(SignData {
      plan: slashing,
      attempt: 0,
      data: vec![preprocess.to_vec()],
      signed: Transaction::empty_signed(),
    });
    tx.sign(&mut OsRng, genesis, our_key);
    publish_tributary_tx(tx).await;
  }
}

// TODO: Once Substrate confirms a key, we need to rotate our validator set OR form a second
// Tributary post-DKG
// https://github.com/serai-dex/serai/issues/426

async fn fatal_slash_with_participant_index<
  D: Db,
  FPtt: Future<Output = ()>,
  PTT: Fn(Transaction) -> FPtt,
>(
  txn: &mut <D as Db>::Transaction<'_>,
  spec: &TributarySpec,
  publish_tributary_tx: &PTT,
  our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  i: Participant,
  reason: &str,
) {
  // Resolve from Participant to <Ristretto as Ciphersuite>::G
  let i = u16::from(i);
  let mut validator = None;
  for (potential, _) in spec.validators() {
    let v_i = spec.i(potential).unwrap();
    if (u16::from(v_i.start) <= i) && (i < u16::from(v_i.end)) {
      validator = Some(potential);
      break;
    }
  }
  let validator = validator.unwrap();

  fatal_slash::<D, _, _>(txn, spec, publish_tributary_tx, our_key, validator.to_bytes(), reason)
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_application_tx<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Fn(ValidatorSet, PstTxType, serai_client::Transaction) -> FPst,
  FPtt: Future<Output = ()>,
  PTT: Fn(Transaction) -> FPtt,
  FRid: Future<Output = ()>,
  RID: RIDTrait<FRid>,
>(
  tx: Transaction,
  spec: &TributarySpec,
  processors: &Pro,
  publish_serai_tx: PST,
  publish_tributary_tx: &PTT,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  txn: &mut <D as Db>::Transaction<'_>,
) {
  let genesis = spec.genesis();

  // Don't handle transactions from fatally slashed participants
  // TODO: Because fatally slashed participants can still publish onto the blockchain, they have
  // a notable DoS ability
  if let TransactionKind::Signed(_, signed) = tx.kind() {
    if FatallySlashed::get(txn, genesis, signed.signer.to_bytes()).is_some() {
      return;
    }
  }

  async fn handle<D: Db, FPtt: Future<Output = ()>, PTT: Fn(Transaction) -> FPtt>(
    txn: &mut <D as Db>::Transaction<'_>,
    spec: &TributarySpec,
    publish_tributary_tx: &PTT,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    data_spec: &DataSpecification,
    bytes: Vec<u8>,
    signed: &Signed,
  ) -> Accumulation {
    let genesis = spec.genesis();

    let Some(curr_attempt) = AttemptDb::attempt(txn, genesis, data_spec.topic) else {
      // Premature publication of a valid ID/publication of an invalid ID
      fatal_slash::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        signed.signer.to_bytes(),
        "published data for ID without an attempt",
      )
      .await;
      return Accumulation::NotReady;
    };

    // If they've already published a TX for this attempt, slash
    // This shouldn't be reachable since nonces were made inserted by the coordinator, yet it's a
    // cheap check to leave in for safety
    if DataDb::get(txn, genesis, data_spec, &signed.signer.to_bytes()).is_some() {
      fatal_slash::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        signed.signer.to_bytes(),
        "published data multiple times",
      )
      .await;
      return Accumulation::NotReady;
    }

    // If the attempt is lesser than the blockchain's, slash
    if data_spec.attempt < curr_attempt {
      // TODO: Slash for being late
      return Accumulation::NotReady;
    }
    // If the attempt is greater, this is a premature publication, full slash
    if data_spec.attempt > curr_attempt {
      fatal_slash::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
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
    DataDb::accumulate(txn, key, spec, data_spec, signed.signer, &bytes)
  }

  async fn check_sign_data_len<D: Db, FPtt: Future<Output = ()>, PTT: Fn(Transaction) -> FPtt>(
    txn: &mut D::Transaction<'_>,
    spec: &TributarySpec,
    publish_tributary_tx: &PTT,
    our_key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    signer: <Ristretto as Ciphersuite>::G,
    len: usize,
  ) -> Result<(), ()> {
    let signer_i = spec.i(signer).unwrap();
    if len != usize::from(u16::from(signer_i.end) - u16::from(signer_i.start)) {
      fatal_slash::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        our_key,
        signer.to_bytes(),
        "signer published a distinct amount of sign data than they had shares",
      )
      .await;
      Err(())?;
    }
    Ok(())
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

  match tx {
    Transaction::RemoveParticipant(i) => {
      fatal_slash_with_participant_index::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        i,
        "RemoveParticipant Provided TX",
      )
      .await
    }
    Transaction::DkgCommitments(attempt, commitments, signed) => {
      let Ok(_) = check_sign_data_len::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        signed.signer,
        commitments.len(),
      )
      .await
      else {
        return;
      };
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification { topic: Topic::Dkg, label: DKG_COMMITMENTS, attempt },
        commitments.encode(),
        &signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(mut commitments)) => {
          log::info!("got all DkgCommitments for {}", hex::encode(genesis));
          unflatten(spec, &mut commitments);
          processors
            .send(
              spec.set().network,
              key_gen::CoordinatorMessage::Commitments {
                id: KeyGenId { session: spec.set().session, attempt },
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
      let sender_i = spec
        .i(signed.signer)
        .expect("transaction added to tributary by signer who isn't a participant");
      let sender_is_len = u16::from(sender_i.end) - u16::from(sender_i.start);

      if shares.len() != usize::from(sender_is_len) {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          signed.signer.to_bytes(),
          "invalid amount of DKG shares by key shares",
        )
        .await;
        return;
      }
      for shares in &shares {
        if shares.len() != (usize::from(spec.n() - sender_is_len)) {
          fatal_slash::<D, _, _>(
            txn,
            spec,
            publish_tributary_tx,
            key,
            signed.signer.to_bytes(),
            "invalid amount of DKG shares",
          )
          .await;
          return;
        }
      }

      // Save each share as needed for blame
      {
        let from_range = spec.i(signed.signer).unwrap();
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

            DkgShare::set(txn, genesis, from.into(), to.into(), share);
          }
        }
      }

      // Filter down to only our share's bytes for handle
      let our_i = spec
        .i(Ristretto::generator() * key.deref())
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

      let confirmation_nonces = handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_NONCES, attempt },
        confirmation_nonces.to_vec(),
        &signed,
      )
      .await;
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification { topic: Topic::Dkg, label: DKG_SHARES, attempt },
        our_shares.encode(),
        &signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(shares)) => {
          log::info!("got all DkgShares for {}", hex::encode(genesis));

          let Accumulation::Ready(DataSet::Participating(confirmation_nonces)) =
            confirmation_nonces
          else {
            panic!("got all DKG shares yet confirmation nonces aren't Ready(Participating(_))");
          };
          ConfirmationNonces::set(txn, genesis, attempt, &confirmation_nonces);

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

          processors
            .send(
              spec.set().network,
              key_gen::CoordinatorMessage::Shares {
                id: KeyGenId { session: spec.set().session, attempt },
                shares: expanded_shares,
              },
            )
            .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {
          panic!("wasn't a participant in DKG shares")
        }
        Accumulation::NotReady => assert!(matches!(confirmation_nonces, Accumulation::NotReady)),
      }
    }

    // TODO: Ban self-accusals
    Transaction::InvalidDkgShare { attempt, accuser, faulty, blame, signed } => {
      let range = spec.i(signed.signer).unwrap();
      if (u16::from(accuser) < u16::from(range.start)) ||
        (u16::from(range.end) <= u16::from(accuser))
      {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          signed.signer.to_bytes(),
          "accused with a Participant index which wasn't theirs",
        )
        .await;
        return;
      }

      if !((u16::from(range.start) <= u16::from(faulty)) &&
        (u16::from(faulty) < u16::from(range.end)))
      {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          signed.signer.to_bytes(),
          "accused self of having an InvalidDkgShare",
        )
        .await;
        return;
      }

      let share = DkgShare::get(txn, genesis, accuser.into(), faulty.into()).unwrap();
      processors
        .send(
          spec.set().network,
          key_gen::CoordinatorMessage::VerifyBlame {
            id: KeyGenId { session: spec.set().session, attempt },
            accuser,
            accused: faulty,
            share,
            blame,
          },
        )
        .await;
    }

    Transaction::DkgConfirmed(attempt, shares, signed) => {
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_SHARES, attempt },
        shares.to_vec(),
        &signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(shares)) => {
          log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

          let preprocesses = ConfirmationNonces::get(txn, genesis, attempt).unwrap();
          // TODO: This can technically happen under very very very specific timing as the txn put
          // happens before DkgConfirmed, yet the txn commit isn't guaranteed to
          let key_pair = CurrentlyCompletingKeyPair::get(txn, genesis).expect(
            "in DkgConfirmed handling, which happens after everyone \
              (including us) fires DkgConfirmed, yet no confirming key pair",
          );
          let sig = match (DkgConfirmer { spec, key, txn, attempt }).complete(
            preprocesses,
            &key_pair,
            shares,
          ) {
            Ok(sig) => sig,
            Err(p) => {
              fatal_slash_with_participant_index::<D, _, _>(
                txn,
                spec,
                publish_tributary_tx,
                key,
                p,
                "invalid DkgConfirmer share",
              )
              .await;
              return;
            }
          };

          DkgCompleted::set(txn, genesis, &());

          publish_serai_tx(
            spec.set(),
            PstTxType::SetKeys,
            SeraiValidatorSets::set_keys(spec.set().network, key_pair, Signature(sig)),
          )
          .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {
          panic!("wasn't a participant in DKG confirmination shares")
        }
        Accumulation::NotReady => {}
      }
    }

    Transaction::DkgRemovalPreprocess(data) => {
      let signer = data.signed.signer;
      // TODO: Only handle this if we're not actively removing this validator
      if (data.data.len() != 1) || (data.data[0].len() != 64) {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          signer.to_bytes(),
          "non-64-byte DKG removal preprocess",
        )
        .await;
        return;
      }
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::DkgRemoval(data.plan),
          label: DKG_REMOVAL_PREPROCESS,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(preprocesses)) => {
          RemovalNonces::set(txn, genesis, data.plan, data.attempt, &preprocesses);

          let Ok(share) =
            (DkgRemoval { spec, key, txn, removing: data.plan, attempt: data.attempt })
              .share(preprocesses)
          else {
            // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
            // slash) and censor transactions (yet don't explicitly ban)
            return;
          };

          let mut tx = Transaction::DkgRemovalPreprocess(SignData {
            plan: data.plan,
            attempt: data.attempt,
            data: vec![share.to_vec()],
            signed: Transaction::empty_signed(),
          });
          tx.sign(&mut OsRng, genesis, key);
          publish_tributary_tx(tx).await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }
    Transaction::DkgRemovalShare(data) => {
      let signer = data.signed.signer;
      if (data.data.len() != 1) || (data.data[0].len() != 32) {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          signer.to_bytes(),
          "non-32-byte DKG removal share",
        )
        .await;
        return;
      }
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::DkgRemoval(data.plan),
          label: DKG_REMOVAL_SHARE,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(shares)) => {
          let preprocesses = RemovalNonces::get(txn, genesis, data.plan, data.attempt).unwrap();

          let Ok((signers, signature)) =
            (DkgRemoval { spec, key, txn, removing: data.plan, attempt: data.attempt })
              .complete(preprocesses, shares)
          else {
            // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
            // slash) and censor transactions (yet don't explicitly ban)
            return;
          };

          // TODO: Only handle this if we're not actively removing any of the signers
          // The created Substrate call will fail if a removed validator was one of the signers
          // Since:
          // 1) publish_serai_tx will block this task until the TX is published
          // 2) We won't scan any more TXs/blocks until we handle this TX
          // The TX *must* be successfully published *before* we start removing any more signers
          // Accordingly, if the signers aren't currently being removed, they won't be removed
          // by the time this transaction is successfully published *unless* a malicious 34%
          // participates with the non-participating 33% to continue operation and produce a
          // distinct removal (since the non-participating won't block in this block)
          // This breaks BFT and is accordingly within bounds

          let tx = serai_client::SeraiValidatorSets::remove_participant(
            spec.set().network,
            SeraiAddress(data.plan),
            signers,
            Signature(signature),
          );
          publish_serai_tx(spec.set(), PstTxType::RemoveParticipant(data.plan), tx).await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }

    Transaction::CosignSubstrateBlock(hash) => {
      AttemptDb::recognize_topic(
        txn,
        genesis,
        Topic::SubstrateSign(SubstrateSignableId::CosigningSubstrateBlock(hash)),
      );

      let block_number = SeraiBlockNumber::get(txn, hash)
        .expect("CosignSubstrateBlock yet didn't save Serai block number");
      processors
        .send(
          spec.set().network,
          coordinator::CoordinatorMessage::CosignSubstrateBlock {
            id: SubstrateSignId {
              session: spec.set().session,
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
        txn,
        genesis,
        Topic::SubstrateSign(SubstrateSignableId::Batch(batch)),
      );
      recognized_id(spec.set(), genesis, RecognizedIdType::Batch, batch.to_vec()).await;
    }

    Transaction::SubstrateBlock(block) => {
      let plan_ids = PlanIds::get(txn, &genesis, block).expect(
        "synced a tributary block finalizing a substrate block in a provided transaction \
          despite us not providing that transaction",
      );

      for id in plan_ids.into_iter() {
        AttemptDb::recognize_topic(txn, genesis, Topic::Sign(id));
        recognized_id(spec.set(), genesis, RecognizedIdType::Plan, id.to_vec()).await;
      }
    }

    Transaction::SubstratePreprocess(data) => {
      let signer = data.signed.signer;
      let Ok(_) = check_sign_data_len::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        signer,
        data.data.len(),
      )
      .await
      else {
        return;
      };
      for data in &data.data {
        if data.len() != 64 {
          fatal_slash::<D, _, _>(
            txn,
            spec,
            publish_tributary_tx,
            key,
            signer.to_bytes(),
            "non-64-byte Substrate preprocess",
          )
          .await;
          return;
        }
      }
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::SubstrateSign(data.plan),
          label: BATCH_PREPROCESS,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(mut preprocesses)) => {
          unflatten(spec, &mut preprocesses);
          processors
            .send(
              spec.set().network,
              coordinator::CoordinatorMessage::SubstratePreprocesses {
                id: SubstrateSignId {
                  session: spec.set().session,
                  id: data.plan,
                  attempt: data.attempt,
                },
                preprocesses: preprocesses
                  .into_iter()
                  .map(|(k, v)| (k, v.try_into().unwrap()))
                  .collect(),
              },
            )
            .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }
    Transaction::SubstrateShare(data) => {
      let Ok(_) = check_sign_data_len::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        data.signed.signer,
        data.data.len(),
      )
      .await
      else {
        return;
      };
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::SubstrateSign(data.plan),
          label: BATCH_SHARE,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(mut shares)) => {
          unflatten(spec, &mut shares);
          processors
            .send(
              spec.set().network,
              coordinator::CoordinatorMessage::SubstrateShares {
                id: SubstrateSignId {
                  session: spec.set().session,
                  id: data.plan,
                  attempt: data.attempt,
                },
                shares: shares
                  .into_iter()
                  .map(|(validator, share)| (validator, share.try_into().unwrap()))
                  .collect(),
              },
            )
            .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }

    Transaction::SignPreprocess(data) => {
      let Ok(_) = check_sign_data_len::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        data.signed.signer,
        data.data.len(),
      )
      .await
      else {
        return;
      };
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::Sign(data.plan),
          label: SIGN_PREPROCESS,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(mut preprocesses)) => {
          unflatten(spec, &mut preprocesses);
          processors
            .send(
              spec.set().network,
              sign::CoordinatorMessage::Preprocesses {
                id: SignId { session: spec.set().session, id: data.plan, attempt: data.attempt },
                preprocesses,
              },
            )
            .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }
    Transaction::SignShare(data) => {
      let Ok(_) = check_sign_data_len::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        data.signed.signer,
        data.data.len(),
      )
      .await
      else {
        return;
      };
      match handle::<D, _, _>(
        txn,
        spec,
        publish_tributary_tx,
        key,
        &DataSpecification {
          topic: Topic::Sign(data.plan),
          label: SIGN_SHARE,
          attempt: data.attempt,
        },
        data.data.encode(),
        &data.signed,
      )
      .await
      {
        Accumulation::Ready(DataSet::Participating(mut shares)) => {
          unflatten(spec, &mut shares);
          processors
            .send(
              spec.set().network,
              sign::CoordinatorMessage::Shares {
                id: SignId { session: spec.set().session, id: data.plan, attempt: data.attempt },
                shares,
              },
            )
            .await;
        }
        Accumulation::Ready(DataSet::NotParticipating) => {}
        Accumulation::NotReady => {}
      }
    }
    Transaction::SignCompleted { plan, tx_hash, first_signer, signature: _ } => {
      log::info!(
        "on-chain SignCompleted claims {} completes {}",
        hex::encode(&tx_hash),
        hex::encode(plan)
      );

      if AttemptDb::attempt(txn, genesis, Topic::Sign(plan)).is_none() {
        fatal_slash::<D, _, _>(
          txn,
          spec,
          publish_tributary_tx,
          key,
          first_signer.to_bytes(),
          "claimed an unrecognized plan was completed",
        )
        .await;
        return;
      };

      // TODO: Confirm this signer hasn't prior published a completion

      processors
        .send(
          spec.set().network,
          sign::CoordinatorMessage::Completed {
            session: spec.set().session,
            id: plan,
            tx: tx_hash,
          },
        )
        .await;
    }
  }
}
