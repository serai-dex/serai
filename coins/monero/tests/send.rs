use core::ops::Deref;
use std::{sync::Mutex, collections::HashSet};
#[cfg(feature = "multisig")]
use std::collections::HashMap;

use lazy_static::lazy_static;
use zeroize::Zeroizing;
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
  ThresholdKeys,
};

use monero_serai::{
  random_scalar,
  wallet::{address::Network, ViewPair, Scanner, SpendableOutput, SignableTransaction},
  rpc::{Rpc}
};

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

fn generate_keys() -> (Zeroizing<curve25519_dalek::scalar::Scalar>, curve25519_dalek::scalar::Scalar) {
  let spend = Zeroizing::new(random_scalar(&mut OsRng));
  let view = random_scalar(&mut OsRng);
  return (spend, view);
}

fn generate_multisig_keys() -> (HashMap<u16, ThresholdKeys<Ed25519>>, curve25519_dalek::scalar::Scalar) {
  let keys = key_gen::<_, Ed25519>(&mut OsRng);
  let view = Scalar::from_hash(Blake2b512::new().chain("Monero Serai Transaction Test")).0;
  return (keys, view);
}

async fn mine_until_unlocked(rpc: &Rpc, addr: &str, tx_hash: [u8; 32]) {
  // mine until tx is in a block
  let mut height = rpc.get_height().await.unwrap();
  let mut found = false;
  while !found {
    let block = rpc.get_block(height - 1).await.unwrap();
    found = match block.txs.iter().find(|&&x| x == tx_hash) {
        Some(_) => { true },
        None => { 
          rpc.mine_regtest_blocks(addr, 1).await.unwrap();
          height += 1;
          false 
        },
    }
  }

  // mine 9 more blocks to unlock the tx
  rpc.mine_regtest_blocks(addr, 9).await.unwrap();
}

async_sequential! {
  async fn send_single_input() {

    let rpc = Rpc::new("http://127.0.0.1:18081".to_string()).unwrap();
    let (spend, view) = generate_keys();
    let spend_pub = spend.deref() * &ED25519_BASEPOINT_TABLE;

    let mut scanner = Scanner::from_view(ViewPair::new(spend_pub, view), Network::Mainnet, Some(HashSet::new()));
    let addr = scanner.address();
    let addr_str = addr.to_string();
    let fee = rpc.get_fee().await.unwrap();

    // mine 90(30 for decoys + 60 to unlock) blocks to have unlocked outputs
    // TODO: check network is regtest
    rpc.mine_regtest_blocks(&addr_str, 90).await.unwrap();

    // grab an unlocked miner tx
    let unlocked_block = rpc.get_height().await.unwrap() - 60;
    let mut tx = rpc.get_block_transactions(unlocked_block).await.unwrap().swap_remove(0);

    for _ in 0..2 {
      // Grab the biggest output of tx
      let output = {
        let mut outputs = scanner.scan_transaction(&tx).ignore_timelock();
        outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount).reverse());
        outputs.swap_remove(0)
      };
      let amount = output.commitment().amount;

      // make a tx and sign
      let mut signable = SignableTransaction::new(
        rpc.get_protocol().await.unwrap(),
        vec![SpendableOutput::from(&rpc, output).await.unwrap()],
        vec![(addr, amount - 10_000_000_000)], // 0.01 xmr buffer for the tx fee
        Some(addr),
        None,
        fee,
      )
      .unwrap();
      tx = signable.sign(&mut OsRng, &rpc, &spend).await.unwrap();

      // publish the tx
      rpc.publish_transaction(&tx).await.unwrap();

      // TODO: Ideally we would only need to directly mine 10 block to unlock the tx.
      // But we have seen that method doesn't always works since there isn't a guarantee that
      // the tx will be immediately mined in the next block and it doesn't in some slow machines.
      // this function guarantees to mine until the tx is unlocked(assuming tx is default locked 10 blocks)
      // but it inevitably mines more than 10 blocks in some cases, hence diverging from the perfect test case scenario.
      // So we might wanna find another solution in the future.
      mine_until_unlocked(&rpc, &addr_str, tx.hash()).await;
    }
  }

  async fn send_multiple_inputs() {
    let rpc = Rpc::new("http://127.0.0.1:18081".to_string()).unwrap();
    let (spend, view) = generate_keys();
    let spend_pub = spend.deref() * &ED25519_BASEPOINT_TABLE;

    let mut scanner = Scanner::from_view(ViewPair::new(spend_pub, view), Network::Mainnet, Some(HashSet::new()));
    let addr = scanner.address();
    let fee = rpc.get_fee().await.unwrap();

    // We actually need 120 decoys for this transaction, so mine until then
    // 120 + 60 (miner TX maturity) + 10 (lock blocks)
    // It is possible for this to be lower, by noting maturity is sufficient regardless of lock
    // blocks, yet that's not currently implemented
    // TODO, if we care
    rpc.mine_regtest_blocks(&addr.to_string(), 200).await.unwrap();
    let start = rpc.get_height().await.unwrap() - 68;

    // spent 8 output
    let mut outputs = vec![];
    let mut amount = 0;
    for i in (start + 1) .. (start + 9) {
      let mut txs = scanner.scan(&rpc, &rpc.get_block(i).await.unwrap()).await.unwrap();
      let output = txs.swap_remove(0).ignore_timelock().swap_remove(0);
      amount += output.commitment().amount;
      outputs.push(output);
    }

    // make a tx and sign
    let mut signable = SignableTransaction::new(
      rpc.get_protocol().await.unwrap(),
      outputs,
      vec![(addr, amount - 10_000_000_000)], // 0.01 xmr buffer for the tx fee
      Some(addr),
      None,
      fee,
    )
    .unwrap();
    let tx = signable.sign(&mut OsRng, &rpc, &spend).await.unwrap();

    // publish the tx
    rpc.publish_transaction(&tx).await.unwrap();
  }
}

#[cfg(feature = "multisig")]
async_sequential! {
  async fn multisig_send_single_input() {
    let rpc = Rpc::new("http://127.0.0.1:18081".to_string()).unwrap();

    // generate keys
    let (keys, view) = generate_multisig_keys();
    let spend_pub = keys[&1].group_key().0;

    // get a view
    let mut scanner = Scanner::from_view(ViewPair::new(spend_pub, view), Network::Mainnet, Some(HashSet::new()));
    let addr = scanner.address();
    let addr_str = addr.to_string();
    let fee = rpc.get_fee().await.unwrap();

    // mine 90(30 for decoys + 60 to unlock) blocks to have unlocked outputs
    // TODO: check network is regtest
    rpc.mine_regtest_blocks(&addr_str, 90).await.unwrap();

    // grab an unlocked miner tx
    let unlocked_block = rpc.get_height().await.unwrap() - 60;
    let mut tx = rpc.get_block_transactions(unlocked_block).await.unwrap().swap_remove(0);

    for _ in 0..2 {
      // Grab the biggest output of tx
      let output = {
        let mut outputs = scanner.scan_transaction(&tx).ignore_timelock();
        outputs.sort_by(|x, y| x.commitment().amount.cmp(&y.commitment().amount).reverse());
        outputs.swap_remove(0)
      };
      let amount = output.commitment().amount;

      // make a tx and sign
      let signable = SignableTransaction::new(
        rpc.get_protocol().await.unwrap(),
        vec![SpendableOutput::from(&rpc, output).await.unwrap()],
        vec![(addr, amount - 10_000_000_000)], // 0.01 xmr buffer for the tx fee
        Some(addr),
        None,
        fee,
      )
      .unwrap();

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
      tx = sign(&mut OsRng, machines, &vec![]);

      // publish the tx
      rpc.publish_transaction(&tx).await.unwrap();

      // unlock the tx
      mine_until_unlocked(&rpc, &addr_str, tx.hash()).await;
    }
  }

  async fn multisig_send_multiple_inputs() {
    let rpc = Rpc::new("http://127.0.0.1:18081".to_string()).unwrap();

    // generate keys
    let (keys, view) = generate_multisig_keys();
    let spend_pub = keys[&1].group_key().0;

    // get a view
    let mut scanner = Scanner::from_view(ViewPair::new(spend_pub, view), Network::Mainnet, Some(HashSet::new()));
    let addr = scanner.address();
    let fee = rpc.get_fee().await.unwrap();

    rpc.mine_regtest_blocks(&addr.to_string(), 200).await.unwrap();
    let start = rpc.get_height().await.unwrap() - 68;

    // spent 8 output
    let mut outputs = vec![];
    let mut amount = 0;
    for i in (start + 1) .. (start + 9) {
      let mut txs = scanner.scan(&rpc, &rpc.get_block(i).await.unwrap()).await.unwrap();
      let output = txs.swap_remove(0).ignore_timelock().swap_remove(0);
      amount += output.commitment().amount;
      outputs.push(output);
    }

    // make a tx and sign
    let signable = SignableTransaction::new(
      rpc.get_protocol().await.unwrap(),
      outputs,
      vec![(addr, amount - 10_000_000_000)], // 0.01 xmr buffer for the tx fee
      Some(addr),
      None,
      fee,
    )
    .unwrap();

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
    let tx = sign(&mut OsRng, machines, &vec![]);

    // publish the tx
    rpc.publish_transaction(&tx).await.unwrap();
  }
}