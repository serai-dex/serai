use rand::rngs::OsRng;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use monero::{
  network::Network,
  util::{key::PublicKey, address::Address}
};

use monero_serai::{
  random_scalar,
  transaction::{self, SignableTransaction},
  rpc::Rpc
};

mod rpc;
use crate::rpc::mine_block;

#[tokio::test]
pub async fn send() {
  let rpc = Rpc::new("http://127.0.0.1:18081".to_string());

  // Generate an address
  let view = random_scalar(&mut OsRng);
  let spend = random_scalar(&mut OsRng);
  let spend_pub = &spend * &ED25519_BASEPOINT_TABLE;

  let addr = Address::standard(
    Network::Mainnet,
    PublicKey { point: spend_pub.compress() },
    PublicKey { point: (&view * &ED25519_BASEPOINT_TABLE).compress() }
  );

  let fee_per_byte = 50000000;
  let fee = fee_per_byte * 2000;

  let mut tx;
  let mut output;
  let mut amount;
  for i in 0 .. 2 {
    let start = rpc.get_height().await.unwrap();
    for _ in 0 .. 7 {
      mine_block(&rpc, addr.to_string()).await.unwrap();
    }

    // Test both a miner output and a normal output
    tx = rpc.get_block_transactions(start).await.unwrap().swap_remove(i);
    output = transaction::scan(&tx, view, spend_pub).swap_remove(0);
    // Test creating a zero change output and a non-zero change output
    amount = output.commitment.amount - fee - u64::try_from(i).unwrap();
    let tx = SignableTransaction::new(
      vec![output], vec![(addr, amount)], addr, fee_per_byte
    ).sign(&mut OsRng, &rpc, &spend).await.unwrap();
    rpc.publish_transaction(&tx).await.unwrap();
  }
}
