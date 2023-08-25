use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use scale::Decode;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use sp_runtime::traits::Verify;

use tokio::time::sleep;

use serai_db::{DbTxn, Db, MemDb};

use processor_messages::{
  key_gen::{self, KeyGenId},
  CoordinatorMessage,
};

use tributary::{TransactionTrait, Tributary};

use crate::{
  tributary::{TributaryDb, Transaction, TributarySpec, scanner::handle_new_blocks},
  tests::{
    MemProcessors, LocalP2p,
    tributary::{new_keys, new_spec, new_tributaries, run_tributaries, wait_for_tx_inclusion},
  },
};

#[tokio::test]
async fn dkg_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let tributaries = new_tributaries(&keys, &spec).await;

  // Run the tributaries in the background
  tokio::spawn(run_tributaries(tributaries.clone()));

  let mut txs = vec![];
  // Create DKG commitments for each key
  for key in &keys {
    let attempt = 0;
    let mut commitments = vec![0; 256];
    OsRng.fill_bytes(&mut commitments);

    let mut tx = Transaction::DkgCommitments(attempt, commitments, Transaction::empty_signed());
    tx.sign(&mut OsRng, spec.genesis(), key, 0);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip().await;

  // Publish all commitments but one
  for (i, tx) in txs.iter().enumerate().skip(1) {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }

  // Wait until these are included
  for tx in txs.iter().skip(1) {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  let expected_commitments: HashMap<_, _> = txs
    .iter()
    .enumerate()
    .map(|(i, tx)| {
      if let Transaction::DkgCommitments(_, commitments, _) = tx {
        (Participant::new((i + 1).try_into().unwrap()).unwrap(), commitments.clone())
      } else {
        panic!("txs had non-commitments");
      }
    })
    .collect();

  async fn new_processors(
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    tributary: &Tributary<MemDb, Transaction, LocalP2p>,
  ) -> (TributaryDb<MemDb>, MemProcessors) {
    let mut scanner_db = TributaryDb(MemDb::new());
    let processors = MemProcessors::new();
    handle_new_blocks::<_, _, _, _, _, _, LocalP2p>(
      &mut scanner_db,
      key,
      |_, _, _, _| async {
        panic!("provided TX caused recognized_id to be called in new_processors")
      },
      &processors,
      |_, _| async { panic!("test tried to publish a new Serai TX in new_processors") },
      spec,
      &tributary.reader(),
    )
    .await;
    (scanner_db, processors)
  }

  // Instantiate a scanner and verify it has nothing to report
  let (mut scanner_db, processors) = new_processors(&keys[0], &spec, &tributaries[0].1).await;
  assert!(processors.0.read().await.is_empty());

  // Publish the last commitment
  let block_before_tx = tributaries[0].1.tip().await;
  assert!(tributaries[0].1.add_transaction(txs[0].clone()).await);
  wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, txs[0].hash()).await;
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;

  // Verify the scanner emits a KeyGen::Commitments message
  handle_new_blocks::<_, _, _, _, _, _, LocalP2p>(
    &mut scanner_db,
    &keys[0],
    |_, _, _, _| async {
      panic!("provided TX caused recognized_id to be called after Commitments")
    },
    &processors,
    |_, _| async { panic!("test tried to publish a new Serai TX after Commitments") },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    let mut expected_commitments = expected_commitments.clone();
    expected_commitments.remove(&Participant::new((1).try_into().unwrap()).unwrap());
    assert_eq!(
      msgs.pop_front().unwrap(),
      CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
        id: KeyGenId { set: spec.set(), attempt: 0 },
        commitments: expected_commitments
      })
    );
    assert!(msgs.is_empty());
  }

  // Verify all keys exhibit this scanner behavior
  for (i, key) in keys.iter().enumerate() {
    let (_, processors) = new_processors(key, &spec, &tributaries[i].1).await;
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    let mut expected_commitments = expected_commitments.clone();
    expected_commitments.remove(&Participant::new((i + 1).try_into().unwrap()).unwrap());
    assert_eq!(
      msgs.pop_front().unwrap(),
      CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
        id: KeyGenId { set: spec.set(), attempt: 0 },
        commitments: expected_commitments
      })
    );
    assert!(msgs.is_empty());
  }

  // Now do shares
  let mut txs = vec![];
  for (k, key) in keys.iter().enumerate() {
    let attempt = 0;

    let mut shares = HashMap::new();
    for i in 0 .. keys.len() {
      if i != k {
        let mut share = vec![0; 256];
        OsRng.fill_bytes(&mut share);
        shares.insert(Participant::new((i + 1).try_into().unwrap()).unwrap(), share);
      }
    }

    let mut tx = Transaction::DkgShares {
      attempt,
      sender_i: Participant::new((k + 1).try_into().unwrap()).unwrap(),
      shares,
      confirmation_nonces: crate::tributary::dkg_confirmation_nonces(key, &spec),
      signed: Transaction::empty_signed(),
    };
    tx.sign(&mut OsRng, spec.genesis(), key, 1);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip().await;
  for (i, tx) in txs.iter().enumerate().skip(1) {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }
  for tx in txs.iter().skip(1) {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  // With just 4 sets of shares, nothing should happen yet
  handle_new_blocks::<_, _, _, _, _, _, LocalP2p>(
    &mut scanner_db,
    &keys[0],
    |_, _, _, _| async {
      panic!("provided TX caused recognized_id to be called after some shares")
    },
    &processors,
    |_, _| async { panic!("test tried to publish a new Serai TX after some shares") },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  assert_eq!(processors.0.read().await.len(), 1);
  assert!(processors.0.read().await[&spec.set().network].is_empty());

  // Publish the final set of shares
  let block_before_tx = tributaries[0].1.tip().await;
  assert!(tributaries[0].1.add_transaction(txs[0].clone()).await);
  wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, txs[0].hash()).await;
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;

  // Each scanner should emit a distinct shares message
  let shares_for = |i: usize| {
    CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares {
      id: KeyGenId { set: spec.set(), attempt: 0 },
      shares: txs
        .iter()
        .enumerate()
        .filter_map(|(l, tx)| {
          if let Transaction::DkgShares { shares, .. } = tx {
            shares
              .get(&Participant::new((i + 1).try_into().unwrap()).unwrap())
              .cloned()
              .map(|share| (Participant::new((l + 1).try_into().unwrap()).unwrap(), share))
          } else {
            panic!("txs had non-shares");
          }
        })
        .collect::<HashMap<_, _>>(),
    })
  };

  // Any scanner which has handled the prior blocks should only emit the new event
  handle_new_blocks::<_, _, _, _, _, _, LocalP2p>(
    &mut scanner_db,
    &keys[0],
    |_, _, _, _| async { panic!("provided TX caused recognized_id to be called after shares") },
    &processors,
    |_, _| async { panic!("test tried to publish a new Serai TX") },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.pop_front().unwrap(), shares_for(0));
    assert!(msgs.is_empty());
  }

  // Yet new scanners should emit all events
  for (i, key) in keys.iter().enumerate() {
    let (_, processors) = new_processors(key, &spec, &tributaries[i].1).await;
    let mut msgs = processors.0.write().await;
    assert_eq!(msgs.len(), 1);
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    let mut expected_commitments = expected_commitments.clone();
    expected_commitments.remove(&Participant::new((i + 1).try_into().unwrap()).unwrap());
    assert_eq!(
      msgs.pop_front().unwrap(),
      CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
        id: KeyGenId { set: spec.set(), attempt: 0 },
        commitments: expected_commitments
      })
    );
    assert_eq!(msgs.pop_front().unwrap(), shares_for(i));
    assert!(msgs.is_empty());
  }

  // Send DkgConfirmed
  let mut substrate_key = [0; 32];
  OsRng.fill_bytes(&mut substrate_key);
  let mut network_key = vec![0; usize::try_from((OsRng.next_u64() % 32) + 32).unwrap()];
  OsRng.fill_bytes(&mut network_key);
  let key_pair = (serai_client::Public(substrate_key), network_key.try_into().unwrap());

  let mut txs = vec![];
  for (k, key) in keys.iter().enumerate() {
    let attempt = 0;
    // This is fine to re-use the one DB as such, due to exactly how this specific call is coded,
    // albeit poor
    let mut txn = scanner_db.0.txn();
    let share =
      crate::tributary::generated_key_pair::<MemDb>(&mut txn, key, &spec, &key_pair).unwrap();
    txn.commit();

    let mut tx = Transaction::DkgConfirmed(attempt, share, Transaction::empty_signed());
    tx.sign(&mut OsRng, spec.genesis(), key, 2);
    txs.push(tx);
  }
  let block_before_tx = tributaries[0].1.tip().await;
  for (i, tx) in txs.iter().enumerate() {
    assert!(tributaries[i].1.add_transaction(tx.clone()).await);
  }
  for tx in txs.iter() {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  // The scanner should successfully try to publish a transaction with a validly signed signature
  handle_new_blocks::<_, _, _, _, _, _, LocalP2p>(
    &mut scanner_db,
    &keys[0],
    |_, _, _, _| async {
      panic!("provided TX caused recognized_id to be called after DKG confirmation")
    },
    &processors,
    |set, tx| {
      let spec = spec.clone();
      let key_pair = key_pair.clone();
      async move {
        let tx = tx.0;
        // Version, Pallet, Call, Network, Key Pair, Signature
        let expected_len = 1 + 1 + 1 + 1 + 32 + 1 + key_pair.1.len() + 64;
        // It's length prefixed
        assert_eq!(tx.len(), 2 + expected_len);
        let expected_len = u16::try_from(expected_len).unwrap();

        // Check the encoded length
        let bottom_six = expected_len & 0b111111;
        let upper_eight = expected_len >> 6;
        assert_eq!(u8::try_from((bottom_six << 2) | 1).unwrap(), tx[0]);
        assert_eq!(u8::try_from(upper_eight).unwrap(), tx[1]);

        // Version
        assert_eq!(tx[2], 4);

        // Pallet
        // TODO

        // Call
        type Call = serai_client::runtime::validator_sets::Call<serai_client::runtime::Runtime>;
        let tx = Call::decode(&mut &tx[4 ..]).unwrap();
        match tx {
          Call::set_keys { network, key_pair: set_key_pair, signature } => {
            assert_eq!(set, spec.set());
            assert_eq!(set.network, network);
            assert_eq!(key_pair, set_key_pair);
            assert!(signature.verify(
              &*serai_client::validator_sets::primitives::set_keys_message(&set, &key_pair),
              &serai_client::Public(
                frost::dkg::musig::musig_key::<Ristretto>(
                  &serai_client::validator_sets::primitives::musig_context(set),
                  &spec
                    .validators()
                    .into_iter()
                    .map(|(validator, _)| validator)
                    .collect::<Vec<_>>()
                )
                .unwrap()
                .to_bytes()
              ),
            ));
          }
          _ => panic!("Serai TX wasn't to set_keys"),
        }
      }
    },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    assert!(processors.0.read().await.get(&spec.set().network).unwrap().is_empty());
  }
}
