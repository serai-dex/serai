use core::time::Duration;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use sp_runtime::traits::Verify;
use serai_client::{
  primitives::Signature,
  validator_sets::primitives::{ValidatorSet, KeyPair},
};

use tokio::time::sleep;

use serai_db::{Get, DbTxn, Db, MemDb};

use processor_messages::{key_gen, CoordinatorMessage};

use tributary::{TransactionTrait, Tributary};

use crate::{
  tributary::{
    Transaction, TributarySpec,
    scanner::{PublishSeraiTransaction, handle_new_blocks},
  },
  tests::{
    MemProcessors, LocalP2p,
    tributary::{new_keys, new_spec, new_tributaries, run_tributaries, wait_for_tx_inclusion},
  },
};

#[tokio::test]
async fn dkg_test() {
  env_logger::init();

  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let full_tributaries = new_tributaries(&keys, &spec).await;
  let mut dbs = vec![];
  let mut tributaries = vec![];
  for (db, p2p, tributary) in full_tributaries {
    dbs.push(db);
    tributaries.push((p2p, tributary));
  }

  // Run the tributaries in the background
  tokio::spawn(run_tributaries(tributaries.clone()));

  let mut txs = vec![];
  // Create DKG participation for each key
  for key in &keys {
    let mut participation = vec![0; 4096];
    OsRng.fill_bytes(&mut participation);

    let mut tx =
      Transaction::DkgParticipation { participation, signed: Transaction::empty_signed() };
    tx.sign(&mut OsRng, spec.genesis(), key);
    txs.push(tx);
  }

  let block_before_tx = tributaries[0].1.tip().await;

  // Publish t-1 participations
  let t = ((keys.len() * 2) / 3) + 1;
  for (i, tx) in txs.iter().take(t - 1).enumerate() {
    assert_eq!(tributaries[i].1.add_transaction(tx.clone()).await, Ok(true));
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  let expected_participations = txs
    .iter()
    .enumerate()
    .map(|(i, tx)| {
      if let Transaction::DkgParticipation { participation, .. } = tx {
        CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Participation {
          session: spec.set().session,
          participant: Participant::new((i + 1).try_into().unwrap()).unwrap(),
          participation: participation.clone(),
        })
      } else {
        panic!("txs wasn't a DkgParticipation");
      }
    })
    .collect::<Vec<_>>();

  async fn new_processors(
    db: &mut MemDb,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    spec: &TributarySpec,
    tributary: &Tributary<MemDb, Transaction, LocalP2p>,
  ) -> MemProcessors {
    let processors = MemProcessors::new();
    handle_new_blocks::<_, _, _, _, _, LocalP2p>(
      db,
      key,
      &|_, _, _, _| async {
        panic!("provided TX caused recognized_id to be called in new_processors")
      },
      &processors,
      &(),
      &|_| async {
        panic!(
          "test tried to publish a new Tributary TX from handle_application_tx in new_processors"
        )
      },
      spec,
      &tributary.reader(),
    )
    .await;
    processors
  }

  // Instantiate a scanner and verify it has the first two participations to report (and isn't
  // waiting for `t`)
  let processors = new_processors(&mut dbs[0], &keys[0], &spec, &tributaries[0].1).await;
  assert_eq!(processors.0.read().await.get(&spec.set().network).unwrap().len(), t - 1);

  // Publish the rest of the participations
  let block_before_tx = tributaries[0].1.tip().await;
  for tx in txs.iter().skip(t - 1) {
    assert_eq!(tributaries[0].1.add_transaction(tx.clone()).await, Ok(true));
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  // Verify the scanner emits all KeyGen::Participations messages
  handle_new_blocks::<_, _, _, _, _, LocalP2p>(
    &mut dbs[0],
    &keys[0],
    &|_, _, _, _| async {
      panic!("provided TX caused recognized_id to be called after DkgParticipation")
    },
    &processors,
    &(),
    &|_| async {
      panic!(
        "test tried to publish a new Tributary TX from handle_application_tx after DkgParticipation"
      )
    },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    let mut msgs = processors.0.write().await;
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.len(), keys.len());
    for expected in &expected_participations {
      assert_eq!(&msgs.pop_front().unwrap(), expected);
    }
    assert!(msgs.is_empty());
  }

  // Verify all keys exhibit this scanner behavior
  for (i, key) in keys.iter().enumerate().skip(1) {
    let processors = new_processors(&mut dbs[i], key, &spec, &tributaries[i].1).await;
    let mut msgs = processors.0.write().await;
    let msgs = msgs.get_mut(&spec.set().network).unwrap();
    assert_eq!(msgs.len(), keys.len());
    for expected in &expected_participations {
      assert_eq!(&msgs.pop_front().unwrap(), expected);
    }
    assert!(msgs.is_empty());
  }

  let mut substrate_key = [0; 32];
  OsRng.fill_bytes(&mut substrate_key);
  let mut network_key = vec![0; usize::try_from((OsRng.next_u64() % 32) + 32).unwrap()];
  OsRng.fill_bytes(&mut network_key);
  let key_pair = KeyPair(serai_client::Public(substrate_key), network_key.try_into().unwrap());

  let mut txs = vec![];
  for (i, key) in keys.iter().enumerate() {
    let mut txn = dbs[i].txn();

    // Claim we've generated the key pair
    crate::tributary::generated_key_pair::<MemDb>(&mut txn, spec.genesis(), &key_pair);

    // Publish the nonces
    let attempt = 0;
    let mut tx = Transaction::DkgConfirmationNonces {
      attempt,
      confirmation_nonces: crate::tributary::dkg_confirmation_nonces(key, &spec, &mut txn, 0),
      signed: Transaction::empty_signed(),
    };
    txn.commit();
    tx.sign(&mut OsRng, spec.genesis(), key);
    txs.push(tx);
  }
  let block_before_tx = tributaries[0].1.tip().await;
  for (i, tx) in txs.iter().enumerate() {
    assert_eq!(tributaries[i].1.add_transaction(tx.clone()).await, Ok(true));
  }
  for tx in &txs {
    wait_for_tx_inclusion(&tributaries[0].1, block_before_tx, tx.hash()).await;
  }

  // This should not cause any new processor event as the processor doesn't handle DKG confirming
  for (i, key) in keys.iter().enumerate() {
    handle_new_blocks::<_, _, _, _, _, LocalP2p>(
      &mut dbs[i],
      key,
      &|_, _, _, _| async {
        panic!("provided TX caused recognized_id to be called after DkgConfirmationNonces")
      },
      &processors,
      &(),
      // The Tributary handler should publish ConfirmationShare itself after ConfirmationNonces
      &|tx| async { assert_eq!(tributaries[i].1.add_transaction(tx).await, Ok(true)) },
      &spec,
      &tributaries[i].1.reader(),
    )
    .await;
    {
      assert!(processors.0.read().await.get(&spec.set().network).unwrap().is_empty());
    }
  }

  // Yet once these TXs are on-chain, the tributary should itself publish the confirmation shares
  // This means in the block after the next block, the keys should be set onto Serai
  // Sleep twice as long as two blocks, in case there's some stability issue
  sleep(Duration::from_secs(
    2 * 2 * u64::from(Tributary::<MemDb, Transaction, LocalP2p>::block_time()),
  ))
  .await;

  struct CheckPublishSetKeys {
    spec: TributarySpec,
    key_pair: KeyPair,
  }
  #[async_trait::async_trait]
  impl PublishSeraiTransaction for CheckPublishSetKeys {
    async fn publish_set_keys(
      &self,
      _db: &(impl Sync + Get),
      set: ValidatorSet,
      key_pair: KeyPair,
      signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
      signature: Signature,
    ) {
      assert_eq!(set, self.spec.set());
      assert_eq!(self.key_pair, key_pair);
      assert!(signature.verify(
        &*serai_client::validator_sets::primitives::set_keys_message(&set, &key_pair),
        &serai_client::Public(
          frost::dkg::musig::musig_key::<Ristretto>(
            &serai_client::validator_sets::primitives::musig_context(set),
            &self
              .spec
              .validators()
              .into_iter()
              .zip(signature_participants)
              .filter_map(|((validator, _), included)| included.then_some(validator))
              .collect::<Vec<_>>()
          )
          .unwrap()
          .to_bytes()
        ),
      ));
    }
  }

  // The scanner should successfully try to publish a transaction with a validly signed signature
  handle_new_blocks::<_, _, _, _, _, LocalP2p>(
    &mut dbs[0],
    &keys[0],
    &|_, _, _, _| async {
      panic!("provided TX caused recognized_id to be called after DKG confirmation")
    },
    &processors,
    &CheckPublishSetKeys { spec: spec.clone(), key_pair: key_pair.clone() },
    &|_| async { panic!("test tried to publish a new Tributary TX from handle_application_tx") },
    &spec,
    &tributaries[0].1.reader(),
  )
  .await;
  {
    assert!(processors.0.read().await.get(&spec.set().network).unwrap().is_empty());
  }
}
