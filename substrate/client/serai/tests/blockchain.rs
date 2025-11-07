use serai_client_serai::*;

#[tokio::test]
async fn main() {
  let serai = Serai::new("http://127.0.0.1:9944".to_string()).unwrap();
  let block = serai.block_by_number(0).await.unwrap();
  assert_eq!(serai.block(block.header.hash()).await.unwrap(), block);
  assert!(serai.finalized(block.header.hash()).await.unwrap());
}
