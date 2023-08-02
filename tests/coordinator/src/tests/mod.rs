use std::time::Duration;

use ciphersuite::{Ciphersuite, Ristretto};

use dockertest::DockerTest;

use crate::*;

pub(crate) const COORDINATORS: usize = 4;
// pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

fn new_test() -> (Vec<(Handles, <Ristretto as Ciphersuite>::F)>, DockerTest) {
  let mut coordinators = vec![];
  let mut test = DockerTest::new();
  for i in 0 .. COORDINATORS {
    let (handles, coord_key, compositions) = coordinator_stack(match i {
      0 => "alice",
      1 => "bob",
      2 => "charlie",
      3 => "dave",
      4 => "eve",
      5 => "ferdie",
      _ => panic!("needed a 6th name for a serai node"),
    });
    coordinators.push((handles, coord_key));
    for composition in compositions {
      test.add_composition(composition);
    }
  }
  (coordinators, test)
}

#[test]
fn stack_test() {
  let (_coordinators, test) = new_test();

  test.run(|_ops| async move {
    tokio::time::sleep(Duration::from_secs(30)).await;
  });
}
