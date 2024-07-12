use monero_address::{Network, MoneroAddress};

// monero-rpc doesn't include a transport
// We can't include the simple-request crate there as then we'd have a cyclical dependency
// Accordingly, we test monero-rpc here (implicitly testing the simple-request transport)
use monero_simple_request_rpc::*;

const ADDRESS: &str =
  "4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey";

#[tokio::test]
async fn test_rpc() {
  use monero_rpc::Rpc;

  let rpc =
    SimpleRequestRpc::new("http://serai:seraidex@127.0.0.1:18081".to_string()).await.unwrap();

  {
    // Test get_height
    let height = rpc.get_height().await.unwrap();
    // The height should be the amount of blocks on chain
    // The number of a block should be its zero-indexed position
    // Accordingly, there should be no block whose number is the height
    assert!(rpc.get_block_by_number(height).await.is_err());
    let block_number = height - 1;
    // There should be a block just prior
    let block = rpc.get_block_by_number(block_number).await.unwrap();

    // Also test the block RPC routes are consistent
    assert_eq!(block.number().unwrap(), block_number);
    assert_eq!(rpc.get_block(block.hash()).await.unwrap(), block);
    assert_eq!(rpc.get_block_hash(block_number).await.unwrap(), block.hash());

    // And finally the hardfork version route
    assert_eq!(rpc.get_hardfork_version().await.unwrap(), block.header.hardfork_version);
  }

  // Test generate_blocks
  for amount_of_blocks in [1, 5] {
    let (blocks, number) = rpc
      .generate_blocks(
        &MoneroAddress::from_str(Network::Mainnet, ADDRESS).unwrap(),
        amount_of_blocks,
      )
      .await
      .unwrap();
    let height = rpc.get_height().await.unwrap();
    assert_eq!(number, height - 1);

    let mut actual_blocks = Vec::with_capacity(amount_of_blocks);
    for i in (height - amount_of_blocks) .. height {
      actual_blocks.push(rpc.get_block_by_number(i).await.unwrap().hash());
    }
    assert_eq!(blocks, actual_blocks);
  }
}

#[tokio::test]
async fn test_decoy_rpc() {
  use monero_rpc::{Rpc, DecoyRpc};

  let rpc =
    SimpleRequestRpc::new("http://serai:seraidex@127.0.0.1:18081".to_string()).await.unwrap();

  // Ensure there's blocks on-chain
  rpc
    .generate_blocks(&MoneroAddress::from_str(Network::Mainnet, ADDRESS).unwrap(), 100)
    .await
    .unwrap();

  // Test get_output_distribution
  // Our documentation for our Rust fn defines it as taking two block numbers
  {
    let distribution_len = rpc.get_output_distribution_end_height().await.unwrap();
    assert_eq!(distribution_len, rpc.get_height().await.unwrap());

    rpc.get_output_distribution(0 ..= distribution_len).await.unwrap_err();
    assert_eq!(
      rpc.get_output_distribution(0 .. distribution_len).await.unwrap().len(),
      distribution_len
    );
    assert_eq!(
      rpc.get_output_distribution(.. distribution_len).await.unwrap().len(),
      distribution_len
    );

    assert_eq!(
      rpc.get_output_distribution(.. (distribution_len - 1)).await.unwrap().len(),
      distribution_len - 1
    );
    assert_eq!(
      rpc.get_output_distribution(1 .. distribution_len).await.unwrap().len(),
      distribution_len - 1
    );

    assert_eq!(rpc.get_output_distribution(0 ..= 0).await.unwrap().len(), 1);
    assert_eq!(rpc.get_output_distribution(0 ..= 1).await.unwrap().len(), 2);
    assert_eq!(rpc.get_output_distribution(1 ..= 1).await.unwrap().len(), 1);

    rpc.get_output_distribution(0 .. 0).await.unwrap_err();
    #[allow(clippy::reversed_empty_ranges)]
    rpc.get_output_distribution(1 .. 0).await.unwrap_err();
  }
}

// This test passes yet requires a mainnet node, which we don't have reliable access to in CI.
/*
#[tokio::test]
async fn test_zero_out_tx_o_indexes() {
  use monero_rpc::Rpc;

  let rpc = SimpleRequestRpc::new("https://node.sethforprivacy.com".to_string()).await.unwrap();

  assert_eq!(
    rpc
      .get_o_indexes(
        hex::decode("17ce4c8feeb82a6d6adaa8a89724b32bf4456f6909c7f84c8ce3ee9ebba19163")
          .unwrap()
          .try_into()
          .unwrap()
      )
      .await
      .unwrap(),
    Vec::<u64>::new()
  );
}
*/
