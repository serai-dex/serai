use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use tributary::{Signed, Block, P2p, Tributary};

use processor_messages::{
  key_gen::{self, KeyGenId},
  sign::{self, SignId},
  coordinator, CoordinatorMessage,
};

use serai_db::DbTxn;

use crate::{
  Db,
  processor::Processor,
  tributary::{TributaryDb, TributarySpec, Transaction},
};

// Handle a specific Tributary block
async fn handle_block<D: Db, Pro: Processor, P: P2p>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  processor: &mut Pro,
  spec: &TributarySpec,
  tributary: &Tributary<D, Transaction, P>,
  block: Block<Transaction>,
) {
  let hash = block.hash();

  let mut event_id = 0;
  for tx in block.transactions {
    if !TributaryDb::<D>::handled_event(&db.0, hash, event_id) {
      let mut txn = db.0.txn();

      let mut handle = |label, needed, id, attempt, mut bytes: Vec<u8>, signed: Signed| {
        // If they've already published a TX for this attempt, slash
        if let Some(data) =
          TributaryDb::<D>::data(label, &txn, tributary.genesis(), id, attempt, &signed.signer)
        {
          if data != bytes {
            // TODO: Full slash
            todo!();
          }

          // TODO: Slash
          return None;
        }

        // If the attempt is lesser than the blockchain's, slash
        let curr_attempt = TributaryDb::<D>::attempt(&txn, tributary.genesis(), id);
        if attempt < curr_attempt {
          // TODO: Slash for being late
          return None;
        }
        if attempt > curr_attempt {
          // TODO: Full slash
          todo!();
        }

        // Store this data
        let received = TributaryDb::<D>::set_data(
          label,
          &mut txn,
          tributary.genesis(),
          id,
          attempt,
          &signed.signer,
          &bytes,
        );

        // If we have all the needed commitments/preprocesses/shares, tell the processor
        if received == needed {
          let mut data = HashMap::new();
          for validator in spec.validators().keys() {
            data.insert(
              spec.i(*validator).unwrap(),
              if validator == &signed.signer {
                bytes.split_off(0)
              } else if let Some(data) =
                TributaryDb::<D>::data(label, &txn, tributary.genesis(), id, attempt, validator)
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
      };

      match tx {
        Transaction::DkgCommitments(attempt, bytes, signed) => {
          if let Some(commitments) =
            handle(b"dkg_commitments", spec.n(), [0; 32], attempt, bytes, signed)
          {
            processor
              .send(CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
                id: KeyGenId { set: spec.set(), attempt },
                commitments,
              }))
              .await;
          }
        }

        Transaction::DkgShares(attempt, mut shares, signed) => {
          if shares.len() != usize::from(spec.n()) {
            // TODO: Full slash
            continue;
          }

          let bytes = shares
            .remove(
              &spec
                .i(Ristretto::generator() * key.deref())
                .expect("in a tributary we're not a validator for"),
            )
            .unwrap();

          if let Some(shares) = handle(b"dkg_shares", spec.n(), [0; 32], attempt, bytes, signed) {
            processor
              .send(CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares {
                id: KeyGenId { set: spec.set(), attempt },
                shares,
              }))
              .await;
          }
        }

        // TODO
        Transaction::ExternalBlock(..) => todo!(),
        Transaction::SeraiBlock(..) => todo!(),

        Transaction::BatchPreprocess(data) => {
          // TODO: Validate data.plan
          if let Some(preprocesses) =
            handle(b"batch_preprocess", spec.t(), data.plan, data.attempt, data.data, data.signed)
          {
            processor
              .send(CoordinatorMessage::Coordinator(
                coordinator::CoordinatorMessage::BatchPreprocesses {
                  id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
                  preprocesses,
                },
              ))
              .await;
          }
        }
        Transaction::BatchShare(data) => {
          // TODO: Validate data.plan
          if let Some(shares) =
            handle(b"batch_share", spec.t(), data.plan, data.attempt, data.data, data.signed)
          {
            processor
              .send(CoordinatorMessage::Coordinator(coordinator::CoordinatorMessage::BatchShares {
                id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
                shares: shares
                  .drain()
                  .map(|(validator, share)| (validator, share.try_into().unwrap()))
                  .collect(),
              }))
              .await;
          }
        }

        Transaction::SignPreprocess(data) => {
          // TODO: Validate data.plan
          if let Some(preprocesses) =
            handle(b"sign_preprocess", spec.t(), data.plan, data.attempt, data.data, data.signed)
          {
            processor
              .send(CoordinatorMessage::Sign(sign::CoordinatorMessage::Preprocesses {
                id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
                preprocesses,
              }))
              .await;
          }
        }
        Transaction::SignShare(data) => {
          // TODO: Validate data.plan
          if let Some(shares) =
            handle(b"sign_share", spec.t(), data.plan, data.attempt, data.data, data.signed)
          {
            processor
              .send(CoordinatorMessage::Sign(sign::CoordinatorMessage::Shares {
                id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
                shares,
              }))
              .await;
          }
        }
      }

      TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // TODO: Trigger any necessary re-attempts
}

pub async fn handle_new_blocks<D: Db, Pro: Processor, P: P2p>(
  db: &mut TributaryDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  processor: &mut Pro,
  spec: &TributarySpec,
  tributary: &Tributary<D, Transaction, P>,
  last_block: &mut [u8; 32],
) {
  // Check if there's been a new Tributary block
  let latest = tributary.tip();
  if latest == *last_block {
    return;
  }

  let mut blocks = vec![tributary.block(&latest).unwrap()];
  while blocks.last().unwrap().parent() != *last_block {
    blocks.push(tributary.block(&blocks.last().unwrap().parent()).unwrap());
  }

  while let Some(block) = blocks.pop() {
    let hash = block.hash();
    handle_block(db, key, processor, spec, tributary, block).await;
    *last_block = hash;
    db.set_last_block(tributary.genesis(), *last_block);
  }
}
