use core::time::Duration;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{Ciphersuite, Ristretto};
use frost::Participant;

use tokio::time::sleep;

use serai_db::MemDb;

use processor_messages::{
  key_gen::{self, KeyGenId},
  CoordinatorMessage,
};

use tributary::{Transaction as TransactionTrait, Tributary};

use crate::{
  processor::MemProcessor,
  LocalP2p,
  tributary::{TributaryDb, Transaction, TributarySpec, scanner::handle_new_blocks},
  tests::tributary::{new_keys, new_spec, new_tributaries, run_tributaries, wait_for_tx_inclusion},
};

#[tokio::test]
async fn dkg_commitments_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let mut tributaries = new_tributaries(&keys, &spec).await;

  // Run the tributaries in the background
  tokio::spawn(run_tributaries(tributaries.clone()));

  let mut txs = vec![];
  // Create DKG commitments for each key
  for key in &keys {
    let attempt = 0;
    let mut commitments = vec![0; 256];
    OsRng.fill_bytes(&mut commitments);

    let mut tx =
      Transaction::DkgCommitments(attempt, commitments.clone(), Transaction::empty_signed());
    tx.sign(&mut OsRng, spec.genesis(), key, 0);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip();

  // Publish all commitments but one
  for (i, tx) in txs.iter().enumerate().skip(1) {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }

  // Wait until these are included
  for tx in txs.iter().skip(1) {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  let expected_msg = CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
    id: KeyGenId { set: spec.set(), attempt: 0 },
    commitments: txs
      .iter()
      .enumerate()
      .map(|(i, tx)| {
        if let Transaction::DkgCommitments(_, commitments, _) = tx {
          (Participant::new((i + 1).try_into().unwrap()).unwrap(), commitments.clone())
        } else {
          panic!("txs had non-commitments");
        }
      })
      .collect(),
  });

  async fn new_processor(
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    tributary: &Tributary<MemDb, Transaction, LocalP2p>,
  ) -> (TributaryDb<MemDb>, MemProcessor, [u8; 32]) {
    let mut scanner_db = TributaryDb(MemDb::new());
    let mut processor = MemProcessor::new();
    let mut last_block = tributary.genesis();
    handle_new_blocks(&mut scanner_db, key, &mut processor, spec, tributary, &mut last_block).await;
    assert!(last_block != tributary.genesis());
    (scanner_db, processor, last_block)
  }

  {
    // Instantiate a scanner and verify it has nothing to report
    let (mut scanner_db, mut processor, mut last_block) =
      new_processor(&keys[0], &spec, &tributaries[0].1).await;
    assert!(processor.0.read().unwrap().is_empty());

    // Publish the last commitment
    assert!(tributaries[0].1.add_transaction(txs[0].clone()).await);
    wait_for_tx_inclusion(&tributaries[0].1, last_block, txs[0].hash()).await;
    sleep(Duration::from_secs(
      (2 * Tributary::<MemDb, Transaction, LocalP2p>::block_time()).into(),
    ))
    .await;

    // Verify the scanner emits a KeyGen::Commitments message
    handle_new_blocks(
      &mut scanner_db,
      &keys[0],
      &mut processor,
      &spec,
      &tributaries[0].1,
      &mut last_block,
    )
    .await;
    let mut msgs = processor.0.write().unwrap();
    assert_eq!(msgs.pop_front().unwrap(), expected_msg);
    assert!(msgs.is_empty());
  }

  // Verify all keys exhibit this scanner behavior
  for (i, key) in keys.iter().enumerate() {
    let (_, processor, _) = new_processor(key, &spec, &tributaries[i].1).await;
    let mut msgs = processor.0.write().unwrap();
    assert_eq!(msgs.pop_front().unwrap(), expected_msg);
    assert!(msgs.is_empty());
  }
}
