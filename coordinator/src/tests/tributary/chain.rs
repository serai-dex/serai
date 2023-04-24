use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng, OsRng};
use futures::{task::Poll, poll};

use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  Ciphersuite, Ristretto,
};

use sp_application_crypto::sr25519;

use serai_client::{
  primitives::{NETWORKS, NetworkId, Amount},
  validator_sets::primitives::{Session, ValidatorSet, ValidatorSetData},
};

use tokio::time::sleep;

use serai_db::MemDb;

use tributary::{Transaction as TransactionTrait, Tributary};

use crate::{
  P2pMessageKind, P2p, LocalP2p,
  tributary::{Transaction, TributarySpec},
};

pub fn new_keys<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> Vec<Zeroizing<<Ristretto as Ciphersuite>::F>> {
  let mut keys = vec![];
  for _ in 0 .. 5 {
    keys.push(Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut *rng)));
  }
  keys
}

pub fn new_spec<R: RngCore + CryptoRng>(
  rng: &mut R,
  keys: &[Zeroizing<<Ristretto as Ciphersuite>::F>],
) -> TributarySpec {
  let mut serai_block = [0; 32];
  rng.fill_bytes(&mut serai_block);

  let start_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

  let set = ValidatorSet { session: Session(0), network: NetworkId::Bitcoin };

  let set_data = ValidatorSetData {
    bond: Amount(100),
    network: NETWORKS[&NetworkId::Bitcoin].clone(),
    participants: keys
      .iter()
      .map(|key| {
        (sr25519::Public((<Ristretto as Ciphersuite>::generator() * **key).to_bytes()), Amount(100))
      })
      .collect::<Vec<_>>()
      .try_into()
      .unwrap(),
  };

  let res = TributarySpec::new(serai_block, start_time, set, set_data);
  assert_eq!(TributarySpec::read::<&[u8]>(&mut res.serialize().as_ref()).unwrap(), res);
  res
}

pub async fn new_tributaries(
  keys: &[Zeroizing<<Ristretto as Ciphersuite>::F>],
  spec: &TributarySpec,
) -> Vec<(LocalP2p, Tributary<MemDb, Transaction, LocalP2p>)> {
  let p2p = LocalP2p::new(keys.len());
  let mut res = vec![];
  for (i, key) in keys.iter().enumerate() {
    res.push((
      p2p[i].clone(),
      Tributary::<_, Transaction, _>::new(
        MemDb::new(),
        spec.genesis(),
        spec.start_time(),
        key.clone(),
        spec.validators(),
        p2p[i].clone(),
      )
      .await
      .unwrap(),
    ));
  }
  res
}

pub async fn run_tributaries(
  mut tributaries: Vec<(LocalP2p, Tributary<MemDb, Transaction, LocalP2p>)>,
) {
  loop {
    for (p2p, tributary) in tributaries.iter_mut() {
      while let Poll::Ready(msg) = poll!(p2p.receive()) {
        match msg.kind {
          P2pMessageKind::Tributary(genesis) => {
            assert_eq!(genesis, tributary.genesis());
            if tributary.handle_message(&msg.msg).await {
              p2p.broadcast(msg.kind, msg.msg).await;
            }
          }
          _ => panic!("unexpected p2p message found"),
        }
      }
    }

    sleep(Duration::from_millis(100)).await;
  }
}

pub async fn wait_for_tx_inclusion(
  tributary: &Tributary<MemDb, Transaction, LocalP2p>,
  mut last_checked: [u8; 32],
  hash: [u8; 32],
) -> [u8; 32] {
  let reader = tributary.reader();
  loop {
    let tip = tributary.tip().await;
    if tip == last_checked {
      sleep(Duration::from_secs(1)).await;
      continue;
    }

    let mut queue = vec![reader.block(&tip).unwrap()];
    let mut block = None;
    while {
      let parent = queue.last().unwrap().parent();
      if parent == tributary.genesis() {
        false
      } else {
        block = Some(reader.block(&parent).unwrap());
        block.as_ref().unwrap().hash() != last_checked
      }
    } {
      queue.push(block.take().unwrap());
    }

    while let Some(block) = queue.pop() {
      for tx in &block.transactions {
        if tx.hash() == hash {
          return block.hash();
        }
      }
    }

    last_checked = tip;
  }
}

#[tokio::test]
async fn tributary_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let mut tributaries = new_tributaries(&keys, &spec).await;

  let mut blocks = 0;
  let mut last_block = spec.genesis();

  // Doesn't use run_tributaries as we want to wind these down at a certain point
  // run_tributaries will run them ad infinitum
  let timeout = SystemTime::now() + Duration::from_secs(65);
  while (blocks < 10) && (SystemTime::now().duration_since(timeout).is_err()) {
    for (p2p, tributary) in tributaries.iter_mut() {
      while let Poll::Ready(msg) = poll!(p2p.receive()) {
        match msg.kind {
          P2pMessageKind::Tributary(genesis) => {
            assert_eq!(genesis, tributary.genesis());
            tributary.handle_message(&msg.msg).await;
          }
          _ => panic!("unexpected p2p message found"),
        }
      }
    }

    let tip = tributaries[0].1.tip().await;
    if tip != last_block {
      last_block = tip;
      blocks += 1;
    }

    sleep(Duration::from_millis(100)).await;
  }

  if blocks != 10 {
    panic!("tributary chain test hit timeout");
  }

  // Handle all existing messages
  for (p2p, tributary) in tributaries.iter_mut() {
    while let Poll::Ready(msg) = poll!(p2p.receive()) {
      match msg.kind {
        P2pMessageKind::Tributary(genesis) => {
          assert_eq!(genesis, tributary.genesis());
          tributary.handle_message(&msg.msg).await;
        }
        _ => panic!("unexpected p2p message found"),
      }
    }
  }

  // handle_message informed the Tendermint machine, yet it still has to process it
  // Sleep for a second accordingly
  // TODO: Is there a better way to handle this?
  sleep(Duration::from_secs(1)).await;

  // All tributaries should agree on the tip
  let mut final_block = None;
  for (_, tributary) in tributaries {
    if final_block.is_none() {
      final_block = Some(tributary.tip().await);
    }
    if tributary.tip().await != final_block.unwrap() {
      panic!("tributary had different tip");
    }
  }
}
