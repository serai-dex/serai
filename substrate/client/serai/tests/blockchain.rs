use serai_client_serai::*;

#[tokio::test]
async fn blockchain() {
  let mut test = dockertest::DockerTest::new();
  let (composition, handle) = serai_substrate_tests::composition(
    "alice",
    serai_docker_tests::fresh_logs_folder(true, "serai-client/blockchain"),
  );
  test.provide_container(composition);
  test
    .run_async(async |ops| {
      let serai = serai_substrate_tests::rpc(&ops, handle).await;
      let block = serai.block_by_number(0).await.unwrap();
      assert_eq!(serai.block(block.header.hash()).await.unwrap(), block);
      assert!(serai.finalized(block.header.hash()).await.unwrap());
    })
    .await;
}
