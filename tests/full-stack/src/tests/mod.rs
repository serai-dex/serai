use std::sync::OnceLock;

use dockertest::DockerTest;

use crate::*;

mod mint_and_burn;

pub(crate) const VALIDATORS: usize = 4;
// pub(crate) const THRESHOLD: usize = ((VALIDATORS * 2) / 3) + 1;

pub(crate) static ONE_AT_A_TIME: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn new_test() -> (Vec<Handles>, DockerTest) {
  let mut validators = vec![];
  let mut test = DockerTest::new();
  for i in 0 .. VALIDATORS {
    let (handles, compositions) = full_stack(match i {
      0 => "Alice",
      1 => "Bob",
      2 => "Charlie",
      3 => "Dave",
      4 => "Eve",
      5 => "Ferdie",
      _ => panic!("needed a 7th name for a serai node"),
    });
    validators.push(handles);
    for composition in compositions {
      test.add_composition(composition);
    }
  }
  (validators, test)
}
