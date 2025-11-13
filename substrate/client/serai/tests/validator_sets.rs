use serai_abi::{
  primitives::{
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ValidatorSet},
  },
  validator_sets::Event,
};

use serai_client_serai::*;

#[tokio::test]
async fn validator_sets() {
  let mut test = dockertest::DockerTest::new();
  let (composition, handle) = serai_substrate_tests::composition(
    "alice",
    serai_docker_tests::fresh_logs_folder(true, "serai-client/validator_sets"),
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

      // The genesis block should have the expected events
      {
        {
          let mut events = serai
            .as_of(serai.block_by_number(0).await.unwrap().header.hash())
            .await
            .unwrap()
            .validator_sets()
            .set_decided_events()
            .await
            .unwrap();
          events.sort_by_key(|event| borsh::to_vec(event).unwrap());
          let mut expected = vec![
            Event::SetDecided {
              set: ValidatorSet { network: NetworkId::Serai, session: Session(0) },
            },
            Event::SetDecided {
              set: ValidatorSet { network: NetworkId::Serai, session: Session(1) },
            },
            Event::SetDecided {
              set: ValidatorSet {
                network: NetworkId::External(ExternalNetworkId::Bitcoin),
                session: Session(0),
              },
            },
            Event::SetDecided {
              set: ValidatorSet {
                network: NetworkId::External(ExternalNetworkId::Ethereum),
                session: Session(0),
              },
            },
            Event::SetDecided {
              set: ValidatorSet {
                network: NetworkId::External(ExternalNetworkId::Monero),
                session: Session(0),
              },
            },
          ];
          expected.sort_by_key(|event| borsh::to_vec(event).unwrap());
          assert_eq!(events, expected);
        }

        assert_eq!(
          serai
            .as_of(serai.block_by_number(0).await.unwrap().header.hash())
            .await
            .unwrap()
            .validator_sets()
            .accepted_handover_events()
            .await
            .unwrap(),
          vec![Event::AcceptedHandover {
            set: ValidatorSet { network: NetworkId::Serai, session: Session(0) }
          }]
        );
      }

      // The next block should not have these events
      {
        assert_eq!(
          serai
            .as_of(serai.block_by_number(1).await.unwrap().header.hash())
            .await
            .unwrap()
            .validator_sets()
            .set_decided_events()
            .await
            .unwrap(),
          vec![],
        );
        assert_eq!(
          serai
            .as_of(serai.block_by_number(1).await.unwrap().header.hash())
            .await
            .unwrap()
            .validator_sets()
            .accepted_handover_events()
            .await
            .unwrap(),
          vec![],
        );
      }

      println!("Finished `serai-client/blockchain` test");
    })
    .await;
}
