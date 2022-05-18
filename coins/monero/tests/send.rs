use std::sync::Mutex;

use lazy_static::lazy_static;

use rand::rngs::OsRng;

#[cfg(feature = "multisig")]
use blake2::{digest::Update, Digest, Blake2b512};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(feature = "multisig")]
use dalek_ff_group::Scalar;

use monero::{
  network::Network,
  util::{key::PublicKey, address::Address}
};
#[cfg(feature = "multisig")]
use monero::cryptonote::hash::Hashable;

use monero_serai::{random_scalar, transaction::{self, SignableTransaction}};

mod rpc;
use crate::rpc::{rpc, mine_block};

#[cfg(feature = "multisig")]
mod frost;
#[cfg(feature = "multisig")]
use crate::frost::{THRESHOLD, generate_keys, sign};

lazy_static! {
  static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

pub async fn send_core(test: usize, multisig: bool) {
  let _guard = SEQUENTIAL.lock().unwrap();
  let rpc = rpc().await;

  // Generate an address
  let spend = random_scalar(&mut OsRng);
  #[allow(unused_mut)]
  let mut view = random_scalar(&mut OsRng);
  #[allow(unused_mut)]
  let mut spend_pub = &spend * &ED25519_BASEPOINT_TABLE;

  #[cfg(feature = "multisig")]
  let (keys, _) = generate_keys();
  #[cfg(feature = "multisig")]
  let t = keys[0].params().t();

  if multisig {
    #[cfg(not(feature = "multisig"))]
    panic!("Running a multisig test without the multisig feature");
    #[cfg(feature = "multisig")]
    {
      view = Scalar::from_hash(Blake2b512::new().chain("Monero Serai Transaction Test")).0;
      spend_pub = keys[0].group_key().0;
    }
  }

  let addr = Address::standard(
    Network::Mainnet,
    PublicKey { point: spend_pub.compress() },
    PublicKey { point: (&view * &ED25519_BASEPOINT_TABLE).compress() }
  );

  // TODO
  let fee_per_byte = 50000000;
  let fee = fee_per_byte * 2000;

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

      let output = transaction::scan(tx.as_ref().unwrap(), view, spend_pub).swap_remove(0);
      // Test creating a zero change output and a non-zero change output
      amount = output.commitment.amount - u64::try_from(i).unwrap();
      outputs.push(output);

    // Test spending multiple inputs
    } else if test == 1 {
      if i != 0 {
        continue;
      }

      for i in (start + 1) .. (start + 9) {
        let tx = rpc.get_block_transactions(i).await.unwrap().swap_remove(0);
        let output = transaction::scan(&tx, view, spend_pub).swap_remove(0);
        amount += output.commitment.amount;
        outputs.push(output);
      }
    }

    let mut signable = SignableTransaction::new(
      outputs, vec![(addr, amount - fee)], addr, fee_per_byte
    ).unwrap();

    if !multisig {
      tx = Some(signable.sign(&mut OsRng, &rpc, &spend).await.unwrap());
    } else {
      #[cfg(feature = "multisig")]
      {
        let mut machines = Vec::with_capacity(t);
        for i in 1 ..= t {
          machines.push(
            signable.clone().multisig(
              b"Monero Serai Test Transaction".to_vec(),
              &mut OsRng,
              &rpc,
              rpc.get_height().await.unwrap() - 10,
              keys[i - 1].clone(),
              &(1 ..= THRESHOLD).collect::<Vec<usize>>()
            ).await.unwrap()
          );
        }

        let mut txs = sign(&mut machines, &vec![]);
        for s in 0 .. (t - 1) {
          assert_eq!(txs[s].hash(), txs[0].hash());
        }
        tx = Some(txs.swap_remove(0));
      }
    }

    rpc.publish_transaction(tx.as_ref().unwrap()).await.unwrap();
    mine_block(&rpc, &addr.to_string()).await.unwrap();
  }
}

#[tokio::test]
pub async fn send_single_input() {
  send_core(0, false).await;
}

#[tokio::test]
pub async fn send_multiple_inputs() {
  send_core(1, false).await;
}

#[cfg(feature = "multisig")]
#[tokio::test]
pub async fn multisig_send_single_input() {
  send_core(0, true).await;
}

#[cfg(feature = "multisig")]
#[tokio::test]
pub async fn multisig_send_multiple_inputs() {
  send_core(1, true).await;
}
