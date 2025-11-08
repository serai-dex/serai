use serai_client_serai::*;

#[tokio::test]
async fn blockchain() {
  let mut test = dockertest::DockerTest::new();
  let (composition, handle) = serai_substrate_tests::composition(
    "alice",
    serai_docker_tests::fresh_logs_folder(true, "serai-client/blockchain"),
  );
  test.provide_container(
    composition
      .replace_cmd(
        ["serai-node", "--unsafe-rpc-external", "--rpc-cors", "all", "--dev"]
          .into_iter()
          .map(str::to_owned)
          .collect(),
      )
      .replace_env([("RUST_LOG".to_string(), "runtime=debug".to_string())].into()),
  );

  test
    .run_async(async |ops| {
      let serai = serai_substrate_tests::rpc(&ops, handle).await;

      let test_block = |number| {
        let serai = &serai;
        async move {
          let block = serai.block_by_number(number).await.unwrap();
          assert_eq!(serai.block(block.header.hash()).await.unwrap(), block);
          assert!(serai.finalized(block.header.hash()).await.unwrap());
        }
      };

      test_block(0).await;
      let finalized = serai.latest_finalized_block_number().await.unwrap();
      test_block(finalized).await;

      let mut next_finalized;
      {
        let mut i = 0;
        while {
          next_finalized = serai.latest_finalized_block_number().await.unwrap();
          next_finalized == finalized
        } {
          tokio::time::sleep(core::time::Duration::from_secs(6)).await;
          i += 1;
          assert!(i < 50, "serai didn't finalize a block within five minutes");
        }
      }
      assert!(next_finalized > finalized);
      test_block(next_finalized).await;

      println!("Finished `serai-client/blockchain` test");
    })
    .await;
}
