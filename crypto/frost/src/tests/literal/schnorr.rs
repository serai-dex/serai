use std::rc::Rc;

use rand::rngs::OsRng;

use crate::{
  Curve, schnorr, algorithm::{Hram, Schnorr},
  tests::{key_gen, algorithm_machines, sign as sign_test, literal::secp256k1::{Secp256k1, TestHram}}
};

const MESSAGE: &[u8] = b"Hello World";

#[test]
fn sign() {
  sign_test(
    &mut OsRng,
    algorithm_machines(
      &mut OsRng,
      Schnorr::<Secp256k1, TestHram>::new(),
      &key_gen::<_, Secp256k1>(&mut OsRng)
    ),
    MESSAGE
  );
}

#[test]
fn sign_with_offset() {
  let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
  let group_key = keys[&1].group_key();

  let offset = Secp256k1::hash_to_F(b"offset");
  for i in 1 ..= u16::try_from(keys.len()).unwrap() {
    keys.insert(i, Rc::new(keys[&i].offset(offset)));
  }
  let offset_key = group_key + (Secp256k1::generator_table() * offset);

  let sig = sign_test(
    &mut OsRng,
    algorithm_machines(&mut OsRng, Schnorr::<Secp256k1, TestHram>::new(), &keys),
    MESSAGE
  );
  assert!(schnorr::verify(offset_key, TestHram::hram(&sig.R, &offset_key, MESSAGE), &sig));
}
