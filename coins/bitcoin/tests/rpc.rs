use bitcoin_serai::{bitcoin::hashes::Hash as HashTrait, rpc::RpcError};

mod runner;
use runner::rpc;

async_sequential! {
  async fn test_rpc() {
    let rpc = rpc().await;

    // Test get_latest_block_number and get_block_hash by round tripping them
    let latest = rpc.get_latest_block_number().await.unwrap();
    let hash = rpc.get_block_hash(latest).await.unwrap();
    assert_eq!(rpc.get_block_number(&hash).await.unwrap(), latest);

    // Test this actually is the latest block number by checking asking for the next block's errors
    assert!(matches!(rpc.get_block_hash(latest + 1).await, Err(RpcError::RequestError(_))));

    // Test get_block by checking the received block's hash matches the request
    let block = rpc.get_block(&hash).await.unwrap();
    // Hashes are stored in reverse. It's bs from Satoshi
    let mut block_hash = block.block_hash().as_hash().into_inner();
    block_hash.reverse();
    assert_eq!(hash, block_hash);
  }
}
