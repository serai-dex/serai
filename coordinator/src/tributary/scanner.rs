use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use tributary::{Signed, Block, P2p, Tributary};

use processor_messages::{
  key_gen::{self, KeyGenId},
  CoordinatorMessage,
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

      let mut handle_dkg = |label, attempt, mut bytes: Vec<u8>, signed: Signed| {
        // If they've already published a TX for this attempt, slash
        if let Some(data) =
          TributaryDb::<D>::dkg_data(label, &txn, tributary.genesis(), &signed.signer, attempt)
        {
          if data != bytes {
            // TODO: Full slash
            todo!();
          }

          // TODO: Slash
          return None;
        }

        // If the attempt is lesser than the blockchain's, slash
        let curr_attempt = TributaryDb::<D>::dkg_attempt(&txn, tributary.genesis());
        if attempt < curr_attempt {
          // TODO: Slash for being late
          return None;
        }
        if attempt > curr_attempt {
          // TODO: Full slash
          todo!();
        }

        // Store this data
        let received = TributaryDb::<D>::set_dkg_data(
          label,
          &mut txn,
          tributary.genesis(),
          &signed.signer,
          attempt,
          &bytes,
        );

        // If we have all commitments/shares, tell the processor
        if received == spec.n() {
          let mut data = HashMap::new();
          for validator in spec.validators().keys() {
            data.insert(
              spec.i(*validator).unwrap(),
              if validator == &signed.signer {
                bytes.split_off(0)
              } else {
                TributaryDb::<D>::dkg_data(label, &txn, tributary.genesis(), validator, attempt)
                  .unwrap_or_else(|| {
                    panic!(
                      "received all DKG data yet couldn't load {} for a validator",
                      std::str::from_utf8(label).unwrap(),
                    )
                  })
              },
            );
          }

          return Some((KeyGenId { set: spec.set(), attempt }, data));
        }
        None
      };

      match tx {
        Transaction::DkgCommitments(attempt, bytes, signed) => {
          if let Some((id, commitments)) = handle_dkg(b"commitments", attempt, bytes, signed) {
            processor
              .send(CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
                id,
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

          if let Some((id, shares)) = handle_dkg(b"shares", attempt, bytes, signed) {
            processor
              .send(CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares { id, shares }))
              .await;
          }
        }

        Transaction::SignPreprocess(..) => todo!(),
        Transaction::SignShare(..) => todo!(),

        Transaction::FinalizedBlock(..) => todo!(),

        Transaction::BatchPreprocess(..) => todo!(),
        Transaction::BatchShare(..) => todo!(),
      }

      TributaryDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }
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
