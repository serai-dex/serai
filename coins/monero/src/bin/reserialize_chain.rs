#[cfg(feature = "binaries")]
mod binaries {
  pub(crate) use std::sync::Arc;

  pub(crate) use curve25519_dalek::{
    scalar::Scalar,
    edwards::{CompressedEdwardsY, EdwardsPoint},
  };

  pub(crate) use multiexp::BatchVerifier;

  pub(crate) use serde::Deserialize;
  pub(crate) use serde_json::json;

  pub(crate) use monero_serai::{
    Commitment,
    ringct::RctPrunable,
    transaction::{Input, Transaction},
    block::Block,
    rpc::{RpcError, Rpc, HttpRpc},
  };

  pub(crate) use tokio::task::JoinHandle;

  pub(crate) async fn check_block(rpc: Arc<Rpc<HttpRpc>>, block_i: usize) {
    let hash = loop {
      match rpc.get_block_hash(block_i).await {
        Ok(hash) => break hash,
        Err(RpcError::ConnectionError(e)) => {
          println!("get_block_hash ConnectionError: {e}");
          continue;
        }
        Err(e) => panic!("couldn't get block {block_i}'s hash: {e:?}"),
      }
    };

    // TODO: Grab the JSON to also check it was deserialized correctly
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String,
    }
    let res: BlockResponse = loop {
      match rpc.json_rpc_call("get_block", Some(json!({ "hash": hex::encode(hash) }))).await {
        Ok(res) => break res,
        Err(RpcError::ConnectionError(e)) => {
          println!("get_block ConnectionError: {e}");
          continue;
        }
        Err(e) => panic!("couldn't get block {block_i} via block.hash(): {e:?}"),
      }
    };

    let blob = hex::decode(res.blob).expect("node returned non-hex block");
    let block = Block::read(&mut blob.as_slice())
      .unwrap_or_else(|e| panic!("couldn't deserialize block {block_i}: {e}"));
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

      let mut hashes_hex = block.txs.iter().map(hex::encode).collect::<Vec<_>>();
      let mut all_txs = vec![];
      while !hashes_hex.is_empty() {
        let txs: TransactionsResponse = loop {
          match rpc
            .rpc_call(
              "get_transactions",
              Some(json!({
                "txs_hashes": hashes_hex.drain(.. hashes_hex.len().min(100)).collect::<Vec<_>>(),
              })),
            )
            .await
          {
            Ok(txs) => break txs,
            Err(RpcError::ConnectionError(e)) => {
              println!("get_transactions ConnectionError: {e}");
              continue;
            }
            Err(e) => panic!("couldn't call get_transactions: {e:?}"),
          }
        };
        assert!(txs.missed_tx.is_empty());
        all_txs.extend(txs.txs);
      }

      let mut batch = BatchVerifier::new(block.txs.len());
      for (tx_hash, tx_res) in block.txs.into_iter().zip(all_txs) {
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

        if matches!(tx.rct_signatures.prunable, RctPrunable::Null) {
          assert_eq!(tx.prefix.version, 1);
          assert!(!tx.signatures.is_empty());
          continue;
        }

        let sig_hash = tx.signature_hash();
        // Verify all proofs we support proving for
        // This is due to having debug_asserts calling verify within their proving, and CLSAG
        // multisig explicitly calling verify as part of its signing process
        // Accordingly, making sure our signature_hash algorithm is correct is great, and further
        // making sure the verification functions are valid is appreciated
        match tx.rct_signatures.prunable {
          RctPrunable::Null | RctPrunable::MlsagBorromean { .. } => {}
          RctPrunable::MlsagBulletproofs { bulletproofs, .. } => {
            assert!(bulletproofs.batch_verify(
              &mut rand_core::OsRng,
              &mut batch,
              (),
              &tx.rct_signatures.base.commitments
            ));
          }
          RctPrunable::Clsag { bulletproofs, clsags, pseudo_outs } => {
            assert!(bulletproofs.batch_verify(
              &mut rand_core::OsRng,
              &mut batch,
              (),
              &tx.rct_signatures.base.commitments
            ));

            for (i, clsag) in clsags.into_iter().enumerate() {
              let (amount, key_offsets, image) = match &tx.prefix.inputs[i] {
                Input::Gen(_) => panic!("Input::Gen"),
                Input::ToKey { amount, key_offsets, key_image } => (amount, key_offsets, key_image),
              };

              let mut running_sum = 0;
              let mut actual_indexes = vec![];
              for offset in key_offsets {
                running_sum += offset;
                actual_indexes.push(running_sum);
              }

              async fn get_outs(
                rpc: &Rpc<HttpRpc>,
                amount: u64,
                indexes: &[u64],
              ) -> Vec<[EdwardsPoint; 2]> {
                #[derive(Deserialize, Debug)]
                struct Out {
                  key: String,
                  mask: String,
                }

                #[derive(Deserialize, Debug)]
                struct Outs {
                  outs: Vec<Out>,
                }

                let outs: Outs = loop {
                  match rpc
                    .rpc_call(
                      "get_outs",
                      Some(json!({
                        "get_txid": true,
                        "outputs": indexes.iter().map(|o| json!({
                          "amount": amount,
                          "index": o
                        })).collect::<Vec<_>>()
                      })),
                    )
                    .await
                  {
                    Ok(outs) => break outs,
                    Err(RpcError::ConnectionError(e)) => {
                      println!("get_outs ConnectionError: {e}");
                      continue;
                    }
                    Err(e) => panic!("couldn't connect to RPC to get outs: {e:?}"),
                  }
                };

                let rpc_point = |point: &str| {
                  CompressedEdwardsY(
                    hex::decode(point)
                      .expect("invalid hex for ring member")
                      .try_into()
                      .expect("invalid point len for ring member"),
                  )
                  .decompress()
                  .expect("invalid point for ring member")
                };

                outs
                  .outs
                  .iter()
                  .map(|out| {
                    let mask = rpc_point(&out.mask);
                    if amount != 0 {
                      assert_eq!(mask, Commitment::new(Scalar::from(1u8), amount).calculate());
                    }
                    [rpc_point(&out.key), mask]
                  })
                  .collect()
              }

              clsag
                .verify(
                  &get_outs(&rpc, amount.unwrap_or(0), &actual_indexes).await,
                  image,
                  &pseudo_outs[i],
                  &sig_hash,
                )
                .unwrap();
            }
          }
        }
      }
      assert!(batch.verify_vartime());
    }

    println!("Deserialized, hashed, and reserialized {block_i} with {} TXs", txs_len);
  }
}

#[cfg(feature = "binaries")]
#[tokio::main]
async fn main() {
  use binaries::*;

  let args = std::env::args().collect::<Vec<String>>();

  // Read start block as the first arg
  let mut block_i = args[1].parse::<usize>().expect("invalid start block");

  // How many blocks to work on at once
  let async_parallelism: usize =
    args.get(2).unwrap_or(&"8".to_string()).parse::<usize>().expect("invalid parallelism argument");

  // Read further args as RPC URLs
  let default_nodes = vec![
    "http://xmr-node.cakewallet.com:18081".to_string(),
    "https://node.sethforprivacy.com".to_string(),
  ];
  let mut specified_nodes = vec![];
  {
    let mut i = 0;
    loop {
      let Some(node) = args.get(3 + i) else { break };
      specified_nodes.push(node.clone());
      i += 1;
    }
  }
  let nodes = if specified_nodes.is_empty() { default_nodes } else { specified_nodes };

  let rpc = |url: String| {
    HttpRpc::new(url.clone())
      .unwrap_or_else(|_| panic!("couldn't create HttpRpc connected to {url}"))
  };
  let main_rpc = rpc(nodes[0].clone());
  let mut rpcs = vec![];
  for i in 0 .. async_parallelism {
    rpcs.push(Arc::new(rpc(nodes[i % nodes.len()].clone())));
  }

  let mut rpc_i = 0;
  let mut handles: Vec<JoinHandle<()>> = vec![];
  let mut height = 0;
  loop {
    let new_height = main_rpc.get_height().await.expect("couldn't call get_height");
    if new_height == height {
      break;
    }
    height = new_height;

    while block_i < height {
      if handles.len() >= async_parallelism {
        // Guarantee one handle is complete
        handles.swap_remove(0).await.unwrap();

        // Remove all of the finished handles
        let mut i = 0;
        while i < handles.len() {
          if handles[i].is_finished() {
            handles.swap_remove(i).await.unwrap();
            continue;
          }
          i += 1;
        }
      }

      handles.push(tokio::spawn(check_block(rpcs[rpc_i].clone(), block_i)));
      rpc_i = (rpc_i + 1) % rpcs.len();
      block_i += 1;
    }
  }
}

#[cfg(not(feature = "binaries"))]
fn main() {
  panic!("To run binaries, please build with `--feature binaries`.");
}
