use std::rc::Rc;

use rand::rngs::OsRng;

use crate::{
  Curve, schnorr, algorithm::{Hram, Schnorr},
  tests::{key_gen, algorithm_machines, sign as sign_test, literal::p256::{P256, IetfP256Hram}}
};

const MESSAGE: &[u8] = b"Hello World";

#[test]
fn sign() {
  sign_test(
    &mut OsRng,
    algorithm_machines(
      &mut OsRng,
      Schnorr::<P256, IetfP256Hram>::new(),
      &key_gen::<_, P256>(&mut OsRng)
    ),
    MESSAGE
  );
}

#[test]
fn sign_with_offset() {
  let mut keys = key_gen::<_, P256>(&mut OsRng);
  let group_key = keys[&1].group_key();

  let offset = P256::hash_to_F(b"offset", &[]);
  for i in 1 ..= u16::try_from(keys.len()).unwrap() {
    keys.insert(i, Rc::new(keys[&i].offset(offset)));
  }
  let offset_key = group_key + (P256::generator_table() * offset);

  let sig = sign_test(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<P256, IetfP256Hram>::new(), &keys),
    MESSAGE
  );
  assert!(schnorr::verify(offset_key, IetfP256Hram::hram(&sig.R, &offset_key, MESSAGE), &sig));
}
