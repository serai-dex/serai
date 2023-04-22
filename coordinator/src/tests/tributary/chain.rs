use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use rand_core::{RngCore, OsRng};

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

use tributary::Tributary;

use crate::{P2pMessageKind, P2p, LocalP2p, processor::MemProcessor, tributary::TributarySpec};

fn new_spec(keys: &[Zeroizing<<Ristretto as Ciphersuite>::F>]) -> TributarySpec {
  let mut serai_block = [0; 32];
  OsRng.fill_bytes(&mut serai_block);

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

  TributarySpec::new(serai_block, start_time, set, set_data)
}

#[tokio::test]
async fn tributary_test() {
  let mut keys = vec![];
  for _ in 0 .. 5 {
    keys.push(Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
  }

  let processor = MemProcessor::new();

  let spec = new_spec(&keys);

  let p2p = LocalP2p::new(keys.len());

  let mut tributaries = vec![];

  for (i, key) in keys.iter().enumerate() {
    tributaries.push(
      Tributary::<_, crate::tributary::Transaction, _>::new(
        MemDb::new(),
        spec.genesis(),
        spec.start_time(),
        key.clone(),
        spec.validators(),
        p2p[i].clone(),
      )
      .await
      .unwrap(),
    );
  }

  let mut blocks = 0;
  let mut last_block = spec.genesis();

  let timeout = SystemTime::now() + Duration::from_secs(70);
  while (blocks < 10) && (SystemTime::now().duration_since(timeout).is_err()) {
    for (i, p2p) in p2p.iter().enumerate() {
      while let Some(msg) = p2p.receive().await {
        match msg.0 {
          P2pMessageKind::Tributary => {
            tributaries[i].handle_message(&msg.1).await;
          }
        }
      }
    }

    let tip = tributaries[0].tip();
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
  for (i, p2p) in p2p.iter().enumerate() {
    while let Some(msg) = p2p.receive().await {
      match msg.0 {
        P2pMessageKind::Tributary => {
          tributaries[i].handle_message(&msg.1).await;
        }
      }
    }
  }

  // All tributaries should agree on the tip
  let mut final_block = None;
  for tributary in tributaries {
    final_block = final_block.or_else(|| Some(tributary.tip()));
    if tributary.tip() != final_block.unwrap() {
      panic!("tributary had different tip");
    }
  }
}
