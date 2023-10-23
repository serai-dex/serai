pub mod tx;
pub mod validator_sets;
pub mod in_instructions;

#[macro_export]
macro_rules! serai_test {
  ($($name: ident: $test: expr)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        use dockertest::{
          PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image, Composition,
          DockerTest,
        };

        serai_docker_tests::build("serai".to_string());

        let mut composition = Composition::with_image(
          Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
        )
        .with_cmd(vec![
          "serai-node".to_string(),
          "--dev".to_string(),
          "--unsafe-rpc-external".to_string(),
          "--rpc-cors".to_string(),
          "all".to_string(),
        ])
        .with_start_policy(StartPolicy::Strict)
        .with_log_options(Some(LogOptions {
          action: LogAction::Forward,
          policy: LogPolicy::Always,
          source: LogSource::Both,
        }));
        composition.publish_all_ports();

        let handle = composition.handle();

        let mut test = DockerTest::new();
        test.add_composition(composition);
        test.run_async(|ops| async move {
          // Sleep until the Substrate RPC starts
          let serai_rpc = ops.handle(&handle).host_port(9944).unwrap();
          let serai_rpc = format!("ws://{}:{}", serai_rpc.0, serai_rpc.1);
          // Bound execution to 60 seconds
          for _ in 0 .. 60 {
            tokio::time::sleep(core::time::Duration::from_secs(1)).await;
            let Ok(client) = Serai::new(&serai_rpc).await else { continue };
            if client.latest_block_hash().await.is_err() {
              continue;
            }
            break;
          }
          #[allow(clippy::redundant_closure_call)]
          $test(Serai::new(&serai_rpc).await.unwrap()).await;
        }).await;
      }
    )*
  }
}
