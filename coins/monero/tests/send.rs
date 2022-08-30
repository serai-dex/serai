use std::{sync::Mutex, collections::HashSet};
#[cfg(feature = "multisig")]
use std::collections::HashMap;

use lazy_static::lazy_static;

use rand_core::OsRng;

#[cfg(feature = "multisig")]
use blake2::{digest::Update, Digest, Blake2b512};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

#[cfg(feature = "multisig")]
use dalek_ff_group::Scalar;
#[cfg(feature = "multisig")]
use transcript::{Transcript, RecommendedTranscript};
#[cfg(feature = "multisig")]
use frost::{
  curve::Ed25519,
  tests::{THRESHOLD, key_gen, sign},
};

use monero_serai::{
  random_scalar,
  wallet::{address::Network, ViewPair, Scanner, SpendableOutput, SignableTransaction},
};

mod rpc;
use crate::rpc::{rpc, mine_block};

lazy_static! {
  static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = SEQUENTIAL.lock().unwrap();
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  };
}

async fn send_core(test: usize, multisig: bool) {
  let rpc = rpc().await;

  // Generate an address
  let spend = random_scalar(&mut OsRng);
  #[allow(unused_mut)]
  let mut view = random_scalar(&mut OsRng);
  #[allow(unused_mut)]
  let mut spend_pub = &spend * &ED25519_BASEPOINT_TABLE;

  #[cfg(feature = "multisig")]
  let keys = key_gen::<_, Ed25519>(&mut OsRng);

  if multisig {
    #[cfg(not(feature = "multisig"))]
    panic!("Running a multisig test without the multisig feature");
    #[cfg(feature = "multisig")]
    {
      view = Scalar::from_hash(Blake2b512::new().chain("Monero Serai Transaction Test")).0;
      spend_pub = keys[&1].group_key().0;
    }
  }

  let view_pair = ViewPair::new(spend_pub, view);
  let mut scanner = Scanner::from_view(view_pair, Network::Mainnet, Some(HashSet::new()));
  let addr = scanner.address();

  let fee = rpc.get_fee().await.unwrap();

  let start = rpc.get_height().await.unwrap();
  for _ in 0 .. 7 {
    mine_block(&rpc, &addr.to_string()).await.unwrap();
  }

  let mut tx = None;
  // Allow tests to test variable transactions
  for i in 0 .. [2, 1][test] {
    let mut outputs = vec![];
    let mut amount = 0;
    // Test spending both a miner output and a normal output
    if test == 0 {
      if i == 0 {
        tx = Some(rpc.get_block_transactions(start).await.unwrap().swap_remove(0));
      }

      // Grab the largest output available
      let output = {
        let mut outputs = scanner.scan_transaction(tx.as_ref().unwrap()).ignore_timelock();
        outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount).reverse());
        outputs.swap_remove(0)
      };
      // Test creating a zero change output and a non-zero change output
      amount = output.commitment().amount - u64::try_from(i).unwrap();
      outputs.push(SpendableOutput::from(&rpc, output).await.unwrap());

    // Test spending multiple inputs
    } else if test == 1 {
      if i != 0 {
        continue;
      }

      // We actually need 120 decoys for this transaction, so mine until then
      // 120 + 60 (miner TX maturity) + 10 (lock blocks)
      // It is possible for this to be lower, by noting maturity is sufficient regardless of lock
      // blocks, yet that's not currently implemented
      // TODO, if we care
      while rpc.get_height().await.unwrap() < 200 {
        mine_block(&rpc, &addr.to_string()).await.unwrap();
      }

      for i in (start + 1) .. (start + 9) {
        let mut txs = scanner.scan(&rpc, &rpc.get_block(i).await.unwrap()).await.unwrap();
        let output = txs.swap_remove(0).ignore_timelock().swap_remove(0);
        amount += output.commitment().amount;
        outputs.push(output);
      }
    }

    let mut signable = SignableTransaction::new(
      rpc.get_protocol().await.unwrap(),
      outputs,
      vec![(addr, amount - 10000000000)],
      Some(addr),
      None,
      fee,
    )
    .unwrap();

    if !multisig {
      tx = Some(signable.sign(&mut OsRng, &rpc, &spend).await.unwrap());
    } else {
      #[cfg(feature = "multisig")]
      {
        let mut machines = HashMap::new();
        for i in 1 ..= THRESHOLD {
          machines.insert(
            i,
            signable
              .clone()
              .multisig(
                &rpc,
                keys[&i].clone(),
                RecommendedTranscript::new(b"Monero Serai Test Transaction"),
                rpc.get_height().await.unwrap() - 10,
                (1 ..= THRESHOLD).collect::<Vec<_>>(),
              )
              .await
              .unwrap(),
          );
        }

        tx = Some(sign(&mut OsRng, machines, &vec![]));
      }
    }

    rpc.publish_transaction(tx.as_ref().unwrap()).await.unwrap();
    mine_block(&rpc, &addr.to_string()).await.unwrap();
  }
}

async_sequential! {
  async fn send_single_input() {
    send_core(0, false).await;
  }

  async fn send_multiple_inputs() {
    send_core(1, false).await;
  }
}

#[cfg(feature = "multisig")]
async_sequential! {
  async fn multisig_send_single_input() {
    send_core(0, true).await;
  }

  async fn multisig_send_multiple_inputs() {
    send_core(1, true).await;
  }
}
