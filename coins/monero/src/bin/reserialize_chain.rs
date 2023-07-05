use std::{sync::Arc, collections::VecDeque};

use serde::Deserialize;
use serde_json::json;

use monero_serai::{
  transaction::Transaction,
  block::Block,
  rpc::{Rpc, HttpRpc},
};

use tokio::task::JoinHandle;

async fn check_block(rpc: Arc<Rpc<HttpRpc>>, block_i: usize) {
  let hash = rpc.get_block_hash(block_i).await.expect("couldn't get block {block_i}'s hash");

  // TODO: Grab the JSON to also check it was deserialized correctly
  #[derive(Deserialize, Debug)]
  struct BlockResponse {
    blob: String,
  }
  let res: BlockResponse = rpc
    .json_rpc_call("get_block", Some(json!({ "hash": hex::encode(hash) })))
    .await
    .expect("couldn't get block {block} via block.hash()");

  let blob = hex::decode(res.blob).expect("node returned non-hex block");
  let block = Block::read(&mut blob.as_slice()).expect("couldn't deserialize block {block_i}");
  assert_eq!(block.hash(), hash, "hash differs");
  assert_eq!(block.serialize(), blob, "serialization differs");

  let txs_len = 1 + block.txs.len();

  if !block.txs.is_empty() {
    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      tx_hash: String,
      as_hex: String,
    }
    #[derive(Deserialize, Debug)]
    struct TransactionsResponse {
      #[serde(default)]
      missed_tx: Vec<String>,
      txs: Vec<TransactionResponse>,
    }

    let txs: TransactionsResponse = rpc
      .rpc_call(
        "get_transactions",
        Some(json!({
          "txs_hashes": block.txs.iter().map(hex::encode).collect::<Vec<_>>()
        })),
      )
      .await
      .expect("couldn't call get_transactions");
    assert!(txs.missed_tx.is_empty());

    for (tx_hash, tx_res) in block.txs.into_iter().zip(txs.txs.into_iter()) {
      assert_eq!(
        tx_res.tx_hash,
        hex::encode(tx_hash),
        "node returned a transaction with different hash"
      );

      let tx = Transaction::read(
        &mut hex::decode(&tx_res.as_hex).expect("node returned non-hex transaction").as_slice(),
      )
      .expect("couldn't deserialize transaction");

      assert_eq!(
        hex::encode(tx.serialize()),
        tx_res.as_hex,
        "Transaction serialization was different"
      );
      assert_eq!(tx.hash(), tx_hash, "Transaction hash was different");
    }
  }

  println!("Deserialized, hashed, and reserialized {block_i} with {} TXs", txs_len);
}

#[tokio::main]
async fn main() {
  let args = std::env::args().collect::<Vec<String>>();

  // Read start block as the first arg
  let mut block_i = args[1].parse::<usize>().expect("invalid start block");

  // How many blocks to work on at once
  let async_parallelism: usize =
    args.get(2).unwrap_or(&"8".to_string()).parse::<usize>().expect("invalid parallelism argument");

  // Read URL as the second arg
  let default_node = "http://xmr-node.cakewallet.com:18081".to_string();
  let url = args.get(3).unwrap_or(&default_node);

  let rpc =
    || HttpRpc::new(url.clone()).expect(&format!("couldn't create HttpRpc connected to {url}"));
  let main_rpc = rpc();
  let mut rpcs = vec![];
  for _ in 0 .. async_parallelism {
    rpcs.push(Arc::new(rpc()));
  }

  let mut rpc_i = 0;
  let mut handles: VecDeque<JoinHandle<()>> = VecDeque::new();
  while block_i < main_rpc.get_height().await.expect("couldn't call get_height") {
    if handles.len() >= async_parallelism {
      // Guarantee one handle is complete
      handles.pop_front().unwrap().await.unwrap();

      // Remove all of the leading handles
      // This ensures, if 100 is taking a while, we don't print we finished anything beyond 107
      while let Some(handle) = handles.get(0) {
        if handle.is_finished() {
          handles.pop_front().unwrap().await.unwrap();
        }
      }
    }

    handles.push_back(tokio::spawn(check_block(rpcs[rpc_i].clone(), block_i)));
    rpc_i = (rpc_i + 1) % rpcs.len();
    block_i += 1;
  }
}
