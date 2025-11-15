use std::collections::HashSet;

use blake2::{Digest, Blake2b256};

use serai_abi::{
  primitives::merkle::UnbalancedMerkleTree, BLOCK_HEADER_LEAF_TAG, BLOCK_HEADER_BRANCH_TAG,
  TRANSACTION_COMMITMENT_LEAF_TAG, TRANSACTION_COMMITMENT_BRANCH_TAG,
  TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG, TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG,
  EVENTS_COMMITMENT_LEAF_TAG, EVENTS_COMMITMENT_BRANCH_TAG,
};

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

      'outer: {
        for _ in 0 .. (5 * 10) {
          tokio::time::sleep(core::time::Duration::from_secs(6)).await;

          let latest_finalized = serai.latest_finalized_block_number().await.unwrap();
          if latest_finalized > 0 {
            break 'outer;
          }
        }
        panic!("finalized block remained the genesis block for over five minutes");
      };

      // Check the sanity of fetching a block
      let test_finalized_block = |number| {
        let serai = &serai;
        async move {
          let block = serai.block_by_number(number).await.unwrap().unwrap();
          assert_eq!(serai.block(block.header.hash()).await.unwrap().unwrap(), block);
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
          let considered_finalized = serai.finalized(block.unwrap().header.hash()).await.unwrap();
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

      // Check the blocks have the expected headers
      {
        let mut last_block_number = serai.latest_finalized_block_number().await.unwrap();
        let mut observed_consensus_commitments = HashSet::new();
        let mut tagged_block_hashes = vec![];
        for i in 0 ..= last_block_number {
          let block = serai.block_by_number(i).await.unwrap().unwrap();

          assert_eq!(block.header.number(), i);

          {
            assert_eq!(
              UnbalancedMerkleTree::new(BLOCK_HEADER_BRANCH_TAG, tagged_block_hashes.clone()).root,
              block.header.builds_upon().root,
            );
            tagged_block_hashes.push({
              let mut tagged = vec![BLOCK_HEADER_LEAF_TAG];
              tagged.extend(&block.header.hash().0);
              Blake2b256::digest(tagged).into()
            });
          }

          {
            let mut start_transaction = [0; 32];
            start_transaction[24 ..].copy_from_slice(&i.to_be_bytes());
            let mut end_transaction = start_transaction;
            end_transaction[.. 16].copy_from_slice(&[0xff; 16]);
            let transactions_iter = core::iter::once(start_transaction)
              .chain(block.transactions.iter().map(serai_abi::Transaction::hash))
              .chain(core::iter::once(end_transaction));

            let events = serai.as_of(block.header.hash()).await.unwrap().events().await.unwrap();
            assert_eq!(events.len(), 2 + block.transactions.len());

            let mut transaction_leaves = vec![];
            let mut events_leaves = vec![];
            for (transaction, events) in transactions_iter.zip(events) {
              {
                let mut tagged = vec![TRANSACTION_COMMITMENT_LEAF_TAG];
                tagged.extend(&transaction);
                transaction_leaves.push(Blake2b256::digest(tagged).into());
              }
              {
                let events = UnbalancedMerkleTree::new(
                  TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG,
                  events
                    .into_iter()
                    .map(|event| {
                      let mut tagged = vec![TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG];
                      tagged.extend(&borsh::to_vec(&event).unwrap());
                      Blake2b256::digest(tagged).into()
                    })
                    .collect(),
                )
                .root;

                let mut tagged = vec![EVENTS_COMMITMENT_LEAF_TAG];
                tagged.extend(&transaction);
                tagged.extend(&events);
                events_leaves.push(Blake2b256::digest(tagged).into());
              }
            }
            assert_eq!(
              UnbalancedMerkleTree::new(TRANSACTION_COMMITMENT_BRANCH_TAG, transaction_leaves).root,
              block.header.transactions_commitment().root
            );
            assert_eq!(
              UnbalancedMerkleTree::new(EVENTS_COMMITMENT_BRANCH_TAG, events_leaves).root,
              block.header.events_commitment().root
            );
          }

          match block.header {
            serai_abi::Header::V1(serai_abi::HeaderV1 {
              unix_time_in_millis,
              consensus_commitment,
              ..
            }) => {
              if i == 0 {
                assert_eq!(unix_time_in_millis, 0);
              } else {
                assert!(unix_time_in_millis != 0);
              }

              // We treat the `consensus_commitment` as opaque, but we do want to make sure it's set
              // This check practically ensures it's being properly defined for each block
              assert!(!observed_consensus_commitments.contains(&consensus_commitment));
              observed_consensus_commitments.insert(consensus_commitment);
            }
          }
        }
      }

      println!("Finished `serai-client/blockchain` test");
    })
    .await;
}
