use std::collections::HashMap;

use core::time::Duration;

use rand_core::OsRng;
use zeroize::Zeroizing;
use serai_abi::validator_sets::primitives::{musig_context, ValidatorSet};

use tokio::time::sleep;

use serai_client::{Transaction, Serai};

use sp_core::{
  sr25519::{Pair, Signature},
  Pair as PairTrait,
};

use ciphersuite::{Ciphersuite, Ristretto};
use frost::dkg::musig::musig;
use schnorrkel::Schnorrkel;

#[allow(dead_code)]
pub async fn publish_tx(serai: &Serai, tx: &Transaction) -> [u8; 32] {
  let mut latest = serai
    .block(serai.latest_finalized_block_hash().await.unwrap())
    .await
    .unwrap()
    .unwrap()
    .number();

  let r = serai.publish(tx).await;
  if r.is_err() {
    // put some delay before panic so that prints on the node side is flushed
    tokio::time::sleep(Duration::from_secs(3)).await;
    r.unwrap();
  }

  // Get the block it was included in
  // TODO: Add an RPC method for this/check the guarantee on the subscription
  let mut ticks = 0;
  loop {
    latest += 1;

    let block = {
      let mut block;
      while {
        block = serai.finalized_block_by_number(latest).await.unwrap();
        block.is_none()
      } {
        sleep(Duration::from_secs(1)).await;
        ticks += 1;

        if ticks > 60 {
          panic!("60 seconds without inclusion in a finalized block");
        }
      }
      block.unwrap()
    };

    for transaction in &block.transactions {
      if transaction == tx {
        return block.hash();
      }
    }
  }
}

#[allow(dead_code)]
pub fn get_musig_of_pairs(pairs: &[Pair], set: ValidatorSet, msg: &[u8]) -> Signature {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key =
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut pair.public().0.as_ref()).unwrap();
    pub_keys.push(public_key);
  }

  let mut threshold_keys = vec![];
  for i in 0 .. pairs.len() {
    let secret_key = <Ristretto as Ciphersuite>::read_F::<&[u8]>(
      &mut pairs[i].as_ref().secret.to_bytes()[.. 32].as_ref(),
    )
    .unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    threshold_keys.push(
      musig::<Ristretto>(&musig_context(set), &Zeroizing::new(secret_key), &pub_keys).unwrap(),
    );
  }

  let mut musig_keys = HashMap::new();
  for tk in threshold_keys {
    musig_keys.insert(tk.params().i(), tk.into());
  }

  let sig = frost::tests::sign_without_caching(
    &mut OsRng,
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys),
    &msg,
  );

  Signature(sig.to_bytes())
}
