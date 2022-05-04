#![cfg(feature = "multisig")]

use rand::rngs::OsRng;

use blake2::{digest::Update, Digest, Blake2b512};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use dalek_ff_group::Scalar;

use monero::{
  cryptonote::hash::Hashable,
  network::Network,
  util::{key::PublicKey, address::Address}
};

use monero_serai::{transaction::{self, SignableTransaction}, rpc::Rpc};

mod rpc;
use crate::rpc::mine_block;

mod frost;
use crate::frost::{THRESHOLD, generate_keys, sign};

#[tokio::test]
pub async fn send_multisig() {
  let rpc = Rpc::new("http://127.0.0.1:18081".to_string());

  let fee_per_byte = 50000000;
  let fee = fee_per_byte * 2000;

  let (keys, _) = generate_keys();
  let t = keys[0].params().t();

  // Generate an address
  let view = Scalar::from_hash(Blake2b512::new().chain("Serai DEX")).0;
  let spend = keys[0].group_key().0;
  let addr = Address::standard(
    Network::Mainnet,
    PublicKey { point: spend.compress() },
    PublicKey { point: (&view * &ED25519_BASEPOINT_TABLE).compress() }
  );

  // Mine blocks to that address
  let start = rpc.get_height().await.unwrap();
  for _ in 0 .. 7 {
    mine_block(&rpc, addr.to_string()).await.unwrap();
  }

  // Get the input TX
  let tx = rpc.get_block_transactions(start).await.unwrap().swap_remove(0);
  let output = transaction::scan(&tx, view, spend).swap_remove(0);
  let amount = output.commitment.amount - fee;

  let mut machines = Vec::with_capacity(t);
  for i in 1 ..= t {
    machines.push(
      SignableTransaction::new(
        vec![output.clone()], vec![(addr, amount)], addr, fee_per_byte
      ).unwrap().multisig(
        &mut OsRng,
        &rpc,
        keys[i - 1].clone(),
        rpc.get_height().await.unwrap() - 10,
        &(1 ..= THRESHOLD).collect::<Vec<usize>>()
      ).await.unwrap()
    );
  }

  let txs = sign(&mut machines, keys);
  for s in 0 .. (t - 1) {
    assert_eq!(txs[s].hash(), txs[0].hash());
  }
  rpc.publish_transaction(&txs[0]).await.unwrap();
}
