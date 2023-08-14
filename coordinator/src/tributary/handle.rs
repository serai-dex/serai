use core::ops::Deref;
use std::collections::HashMap;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::Participant;

use zeroize::Zeroizing;

use tokio::sync::mpsc::UnboundedSender;

use crate::processors::Processors;
use processor_messages::{
  CoordinatorMessage, coordinator,
  key_gen::{self, KeyGenId},
  sign::{self, SignId},
};

use serai_db::Db;

use tributary::Signed;

use super::{Transaction, TributarySpec, TributaryDb, scanner::RecognizedIdType};

// Used to determine if an ID is acceptable
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Zone {
  Dkg,
  Batch,
  Sign,
}

impl Zone {
  fn label(&self) -> &'static str {
    match self {
      Zone::Dkg => {
        panic!("getting the label for dkg despite dkg code paths not needing a label")
      }
      Zone::Batch => "batch",
      Zone::Sign => "sign",
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn handle<D: Db>(
  zone: Zone,
  label: &'static [u8],
  needed: u16,
  id: [u8; 32],
  attempt: u32,
  mut bytes: Vec<u8>,
  signed: Signed,
  genesis: [u8; 32],
  spec: &TributarySpec,
  txn: &mut <D as Db>::Transaction<'_>,
) -> Option<HashMap<Participant, Vec<u8>>> {
  // let label = label.to_owned();
  if zone == Zone::Dkg {
    // Since Dkg doesn't have an ID, solely attempts, this should just be [0; 32]
    assert_eq!(id, [0; 32], "DKG, which shouldn't have IDs, had a non-0 ID");
  } else if !TributaryDb::<D>::recognized_id(txn, zone.label(), genesis, id) {
    // TODO: Full slash
    todo!();
  }

  // If they've already published a TX for this attempt, slash
  if let Some(data) = TributaryDb::<D>::data(label, txn, genesis, id, attempt, signed.signer) {
    if data != bytes {
      // TODO: Full slash
      todo!();
    }

    // TODO: Slash
    return None;
  }

  // If the attempt is lesser than the blockchain's, slash
  let curr_attempt = TributaryDb::<D>::attempt(txn, genesis, id);
  if attempt < curr_attempt {
    // TODO: Slash for being late
    return None;
  }
  if attempt > curr_attempt {
    // TODO: Full slash
    todo!();
  }

  // TODO: We can also full slash if shares before all commitments, or share before the
  // necessary preprocesses

  // TODO: If this is shares, we need to check they are part of the selected signing set

  // Store this data
  let received =
    TributaryDb::<D>::set_data(label, txn, genesis, id, attempt, signed.signer, &bytes);

  // If we have all the needed commitments/preprocesses/shares, tell the processor
  // TODO: This needs to be coded by weight, not by validator count
  if received == needed {
    let mut data = HashMap::new();
    for validator in spec.validators().iter().map(|validator| validator.0) {
      data.insert(
        spec.i(validator).unwrap(),
        if validator == signed.signer {
          bytes.split_off(0)
        } else if let Some(data) =
          TributaryDb::<D>::data(label, txn, genesis, id, attempt, validator)
        {
          data
        } else {
          continue;
        },
      );
    }
    assert_eq!(data.len(), usize::from(needed));

    return Some(data);
  }
  None
}

pub async fn handle_application_tx<D: Db, Pro: Processors>(
  tx: Transaction,
  spec: &TributarySpec,
  processors: &Pro,
  genesis: [u8; 32],
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: &UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
  txn: &mut <D as Db>::Transaction<'_>,
) {
  match tx {
    Transaction::DkgCommitments(attempt, bytes, signed) => {
      if let Some(commitments) =
        handle(&mut txn, Zone::Dkg, b"dkg_commitments", spec.n(), [0; 32], attempt, bytes, &signed)
      {
        log::info!("got all DkgCommitments for {}", hex::encode(genesis));
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
              id: KeyGenId { set: spec.set(), attempt },
              commitments,
            }),
          )
          .await;
      }
    }

    Transaction::DkgShares { attempt, sender_i, mut shares, confirmation_nonces, signed } => {
      if sender_i !=
        spec
          .i(signed.signer)
          .expect("transaction added to tributary by signer who isn't a participant")
      {
        // TODO: Full slash
        todo!();
      }

      if shares.len() != (usize::from(spec.n()) - 1) {
        // TODO: Full slash
        todo!();
      }

      // Only save our share's bytes
      let our_i = spec
        .i(Ristretto::generator() * key.deref())
        .expect("in a tributary we're not a validator for");
      // This unwrap is safe since the length of shares is checked, the the only missing key
      // within the valid range will be the sender's i
      let bytes = if sender_i == our_i { vec![] } else { shares.remove(&our_i).unwrap() };

      let confirmation_nonces = handle(
        &mut txn,
        Zone::Dkg,
        DKG_CONFIRMATION_NONCES,
        spec.n(),
        [0; 32],
        attempt,
        confirmation_nonces.to_vec(),
        &signed,
      );
      if let Some(shares) =
        handle(&mut txn, Zone::Dkg, b"dkg_shares", spec.n(), [0; 32], attempt, bytes, &signed)
      {
        log::info!("got all DkgShares for {}", hex::encode(genesis));
        assert!(confirmation_nonces.is_some());
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares {
              id: KeyGenId { set: spec.set(), attempt },
              shares,
            }),
          )
          .await;
      } else {
        assert!(confirmation_nonces.is_none());
      }
    }

    Transaction::DkgConfirmed(attempt, shares, signed) => {
      if let Some(shares) = handle(
        &mut txn,
        Zone::Dkg,
        DKG_CONFIRMATION_SHARES,
        spec.n(),
        [0; 32],
        attempt,
        shares.to_vec(),
        &signed,
      ) {
        log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

        let preprocesses = read_known_to_exist_data::<D, _>(
          &txn,
          spec,
          key,
          DKG_CONFIRMATION_NONCES,
          [0; 32],
          spec.n(),
          attempt,
          vec![],
          None,
        );

        let key_pair = TributaryDb::<D>::currently_completing_key_pair(&txn, genesis)
          .unwrap_or_else(|| {
            panic!(
              "in DkgConfirmed handling, which happens after everyone {}",
              "(including us) fires DkgConfirmed, yet no confirming key pair"
            )
          });
        let Ok(sig) = DkgConfirmer::complete(spec, key, preprocesses, &key_pair, shares) else {
          // TODO: Full slash
          todo!();
        };

        publish_serai_tx(
          spec.set(),
          Serai::set_validator_set_keys(spec.set().network, key_pair, Signature(sig)),
        )
        .await;
      }
    }

    Transaction::ExternalBlock(block) => {
      // Because this external block has been finalized, its batch ID should be authorized
      TributaryDb::<D>::recognize_id(&mut txn, Zone::Batch.label(), genesis, block);
      recognized_id
        .send((genesis, RecognizedIdType::Block, block))
        .expect("recognized_id_recv was dropped. are we shutting down?");
    }

    Transaction::SubstrateBlock(block) => {
      let plan_ids = TributaryDb::<D>::plan_ids(&txn, genesis, block).expect(
        "synced a tributary block finalizing a substrate block in a provided transaction \
      despite us not providing that transaction",
      );

      for id in plan_ids {
        TributaryDb::<D>::recognize_id(&mut txn, Zone::Sign.label(), genesis, id);
        recognized_id
          .send((genesis, RecognizedIdType::Plan, id))
          .expect("recognized_id_recv was dropped. are we shutting down?");
      }
    }

    Transaction::SubstrateBlock(block) => {
      let plan_ids = TributaryDb::<D>::plan_ids(&txn, genesis, block).expect(
        "synced a tributary block finalizing a substrate block in a provided transaction \
        despite us not providing that transaction",
      );

      for id in plan_ids {
        TributaryDb::<D>::recognize_id(&mut txn, Zone::Sign.label(), genesis, id);
        recognized_id
          .send((genesis, RecognizedIdType::Plan, id))
          .expect("recognized_id_recv was dropped. are we shutting down?");
      }
    }

    Transaction::BatchPreprocess(data) => {
      if let Some(preprocesses) = handle(
        &mut txn,
        Zone::Batch,
        b"batch_preprocess",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Coordinator(coordinator::CoordinatorMessage::BatchPreprocesses {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              preprocesses,
            }),
          )
          .await;
      }
    }
    Transaction::BatchShare(data) => {
      if let Some(shares) = handle(
        &mut txn,
        Zone::Batch,
        b"batch_share",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Coordinator(coordinator::CoordinatorMessage::BatchShares {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              shares: shares
                .drain()
                .map(|(validator, share)| (validator, share.try_into().unwrap()))
                .collect(),
            }),
          )
          .await;
      }
    }

    Transaction::SignPreprocess(data) => {
      if let Some(preprocesses) = handle(
        &mut txn,
        Zone::Sign,
        b"sign_preprocess",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Sign(sign::CoordinatorMessage::Preprocesses {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              preprocesses,
            }),
          )
          .await;
      }
    }
    Transaction::SignShare(data) => {
      if let Some(shares) = handle(
        &mut txn,
        Zone::Sign,
        b"sign_share",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Sign(sign::CoordinatorMessage::Shares {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              shares,
            }),
          )
          .await;
      }
    }
    Transaction::SignCompleted(_, _, _) => todo!(),
  }
}
