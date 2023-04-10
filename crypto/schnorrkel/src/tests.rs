use rand_core::OsRng;

use group::GroupEncoding;
use frost::{
  Participant,
  tests::{key_gen, algorithm_machines, sign},
};

use schnorrkel::{keys::PublicKey, context::SigningContext};

use crate::Schnorrkel;

#[test]
fn test() {
  const CONTEXT: &[u8] = b"FROST Schnorrkel Test";
  const MSG: &[u8] = b"Hello, World!";

  let keys = key_gen(&mut OsRng);
  let key = keys[&Participant::new(1).unwrap()].group_key();
  let machines = algorithm_machines(&mut OsRng, Schnorrkel::new(CONTEXT), &keys);
  let signature = sign(&mut OsRng, Schnorrkel::new(CONTEXT), keys, machines, MSG);

  let key = PublicKey::from_bytes(key.to_bytes().as_ref()).unwrap();
  key.verify(&mut SigningContext::new(CONTEXT).bytes(MSG), &signature).unwrap()
}
