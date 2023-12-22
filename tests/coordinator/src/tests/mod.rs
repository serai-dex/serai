use std::sync::OnceLock;

use dockertest::DockerTest;

use crate::*;

mod key_gen;
pub use key_gen::key_gen;

mod batch;
pub use batch::batch;

mod sign;
#[allow(unused_imports)]
pub use sign::sign;

pub(crate) const COORDINATORS: usize = 4;
pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

pub(crate) static ONE_AT_A_TIME: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) async fn new_test<F: Send + core::future::Future>(
  test_body: impl 'static + Send + Sync + FnOnce(Vec<Processor>) -> F,
) {
  let _one_at_a_time = ONE_AT_A_TIME.get_or_init(|| Mutex::new(())).lock();

  let mut coordinators = vec![];
  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  for i in 0 .. COORDINATORS {
    let (handles, coord_key, compositions) = coordinator_stack(match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    });
    coordinators.push((handles, coord_key));
    for composition in compositions {
      test.provide_container(composition);
    }
  }
  test
    .run_async(|ops| async move {
      // Wait for the Serai node to boot, and for the Tendermint chain to get past the first block
      // TODO: Replace this with a Coordinator RPC
      tokio::time::sleep(Duration::from_secs(150)).await;

      // Sleep even longer if in the CI due to it being slower than commodity hardware
      if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
        tokio::time::sleep(Duration::from_secs(120)).await;
      }

      // Connect to the Message Queues as the processor
      let mut processors: Vec<Processor> = vec![];
      for (i, (handles, key)) in coordinators.into_iter().enumerate() {
        processors.push(
          Processor::new(i.try_into().unwrap(), NetworkId::Bitcoin, &ops, handles, key).await,
        );
      }

      test_body(processors).await;
    })
    .await;
}

// TODO: Don't use a pessimistic sleep
// Use an RPC to enaluate if a condition was met, with the following time being a timeout
// https://github.com/serai-dex/serai/issues/340
pub(crate) async fn wait_for_tributary() {
  tokio::time::sleep(Duration::from_secs(15)).await;
  if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
    tokio::time::sleep(Duration::from_secs(6)).await;
  }
}
