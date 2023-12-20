use serai_client::{primitives::NetworkId, Serai};

#[tokio::test]
async fn dht() {
  use dockertest::{
    PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image,
    TestBodySpecification, DockerTest,
  };

  serai_docker_tests::build("serai".to_string());

  let handle = |name| format!("serai_client-serai_node-{name}");
  let composition = |name| {
    TestBodySpecification::with_image(
      Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
    )
    .replace_cmd(vec![
      "serai-node".to_string(),
      "--unsafe-rpc-external".to_string(),
      "--rpc-cors".to_string(),
      "all".to_string(),
      "--chain".to_string(),
      "local".to_string(),
      format!("--{name}"),
    ])
    .set_publish_all_ports(true)
    .set_handle(handle(name))
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::Always,
      source: LogSource::Both,
    }))
  };

  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  test.provide_container(composition("alice"));
  test.provide_container(composition("bob"));
  test.provide_container(composition("charlie"));
  test.provide_container(composition("dave"));
  test
    .run_async(|ops| async move {
      // Sleep until the Substrate RPC starts
      let alice = handle("alice");
      let serai_rpc = ops.handle(&alice).host_port(9944).unwrap();
      let serai_rpc = format!("http://{}:{}", serai_rpc.0, serai_rpc.1);
      // Sleep for a minute
      tokio::time::sleep(core::time::Duration::from_secs(60)).await;
      // Check the DHT has been populated
      assert!(!Serai::new(serai_rpc.clone())
        .await
        .unwrap()
        .p2p_validators(NetworkId::Bitcoin)
        .await
        .unwrap()
        .is_empty());
    })
    .await;
}
