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

      // Check the sanity of fetching a block
      let test_finalized_block = |number| {
        let serai = &serai;
        async move {
          let block = serai.block_by_number(number).await.unwrap();
          assert_eq!(serai.block(block.header.hash()).await.unwrap(), block);
          assert!(serai.finalized(block.header.hash()).await.unwrap());
        }
      };

      test_finalized_block(0).await;
      let finalized = serai.latest_finalized_block_number().await.unwrap();
      test_finalized_block(finalized).await;

      // Check unfinalized blocks are marked as unfinalized
      'outer: {
        for _ in 0 .. 10 {
          tokio::time::sleep(core::time::Duration::from_secs(6)).await;

          let latest_finalized = serai.latest_finalized_block_number().await.unwrap();
          // Fetch the unfinalized block after, if it exists
          let Ok(block) = serai.block_by_number(latest_finalized + 1).await else {
            continue;
          };
          // Check if it's considered finalized
          let considered_finalized = serai.finalized(block.header.hash()).await.unwrap();
          // Ensure the finalized block is the same, meaning this block didn't become finalized as
          // we made these RPC requests
          if latest_finalized != serai.latest_finalized_block_number().await.unwrap() {
            continue;
          }

          // Check the block wasn't considered finalized
          assert!(!considered_finalized);
          break 'outer;
        }
        panic!("couldn't find an unfinalized block to check wasn't considered finalized");
      };

      // Check the finalized block advances
      {
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
        test_finalized_block(next_finalized).await;
      }

      println!("Finished `serai-client/blockchain` test");
    })
    .await;
}
