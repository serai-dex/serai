use dockertest::{
  PullPolicy, StartPolicy, LogOptions, LogAction, LogPolicy, LogSource, Image,
  TestBodySpecification, DockerOperations, DockerTest,
};

#[cfg(feature = "bitcoin")]
mod bitcoin {
  use super::*;
  use crate::networks::{Network, Bitcoin};

  #[test]
  fn test_dust_constant() {
    struct IsTrue<const V: bool>;
    trait True {}
    impl True for IsTrue<true> {}
    fn check<T: True>() {
      core::hint::black_box(());
    }
    check::<IsTrue<{ Bitcoin::DUST >= bitcoin_serai::wallet::DUST }>>();
  }

  fn spawn_bitcoin() -> DockerTest {
    serai_docker_tests::build("bitcoin".to_string());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::OnError,
      source: LogSource::Both,
    }))
    .set_publish_all_ports(true);

    let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
    test.provide_container(composition);
    test
  }

  async fn bitcoin(ops: &DockerOperations) -> Bitcoin {
    let handle = ops.handle("serai-dev-bitcoin").host_port(8332).unwrap();
    let bitcoin = Bitcoin::new(format!("http://serai:seraidex@{}:{}", handle.0, handle.1)).await;
    bitcoin.fresh_chain().await;
    bitcoin
  }

  test_network!(
    Bitcoin,
    spawn_bitcoin,
    bitcoin,
    bitcoin_key_gen,
    bitcoin_scanner,
    bitcoin_signer,
    bitcoin_wallet,
    bitcoin_addresses,
    bitcoin_no_deadlock_in_multisig_completed,
  );
}

#[cfg(feature = "monero")]
mod monero {
  use super::*;
  use crate::networks::{Network, Monero};

  fn spawn_monero() -> DockerTest {
    serai_docker_tests::build("monero".to_string());

    let composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict)
    .set_log_options(Some(LogOptions {
      action: LogAction::Forward,
      policy: LogPolicy::OnError,
      source: LogSource::Both,
    }))
    .set_publish_all_ports(true);

    let mut test = DockerTest::new();
    test.provide_container(composition);
    test
  }

  async fn monero(ops: &DockerOperations) -> Monero {
    let handle = ops.handle("serai-dev-monero").host_port(18081).unwrap();
    let monero = Monero::new(format!("http://serai:seraidex@{}:{}", handle.0, handle.1)).await;
    while monero.get_latest_block_number().await.unwrap() < 150 {
      monero.mine_block().await;
    }
    monero
  }

  test_network!(
    Monero,
    spawn_monero,
    monero,
    monero_key_gen,
    monero_scanner,
    monero_signer,
    monero_wallet,
    monero_addresses,
    monero_no_deadlock_in_multisig_completed,
  );
}
