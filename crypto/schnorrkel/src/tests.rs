use rand_core::OsRng;

use frost::tests::{key_gen, algorithm_machines, sign};

use crate::Schnorrkel;

#[test]
fn test() {
  let keys = key_gen(&mut OsRng);
  const CONTEXT: &[u8] = b"FROST Schnorrkel Test";
  let machines = algorithm_machines(&mut OsRng, Schnorrkel::new(CONTEXT), &keys);
  const MSG: &[u8] = b"Hello, World!";
  sign(&mut OsRng, Schnorrkel::new(CONTEXT), keys, machines, MSG);
}
