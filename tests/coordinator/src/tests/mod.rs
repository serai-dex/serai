use ciphersuite::Ristretto;

use dockertest::DockerTest;

use crate::*;

mod key_gen;
pub use key_gen::key_gen;

mod batch;
pub use batch::batch;

mod sign;
pub use sign::sign;

pub(crate) const COORDINATORS: usize = 4;
pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

pub(crate) fn new_test() -> (Vec<(Handles, <Ristretto as Ciphersuite>::F)>, DockerTest) {
  let mut coordinators = vec![];
  let mut test = DockerTest::new();
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
      test.add_composition(composition);
    }
  }
  (coordinators, test)
}

// TODO: Don't use a pessimistic sleep
// Use an RPC to enaluate if a condition was met, with the following time being a timeout
// https://github.com/serai-dex/serai/issues/340
pub(crate) async fn wait_for_tributary() {
  tokio::time::sleep(Duration::from_secs(20)).await;
  if std::env::var("GITHUB_CI") == Ok("true".to_string()) {
    tokio::time::sleep(Duration::from_secs(60)).await;
  }
}
