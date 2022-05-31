use rand::rngs::OsRng;

use ff::Field;
use k256::Scalar;

#[cfg(feature = "multisig")]
use frost::tests::{key_gen, algorithm_machines, sign};

use crate::spark::{F, G, H, U, chaum::*};
#[cfg(feature = "multisig")]
use crate::spark::frost::{Transcript, Secp256k1};

#[test]
fn chaum() {
  #[allow(non_snake_case)]
  let mut S_T = vec![];
  let mut xz = vec![];
  let y = Scalar::random(&mut OsRng);
  for _ in 0 .. 2 {
    let x = Scalar::random(&mut OsRng);
    let z = Scalar::random(&mut OsRng);

    S_T.push((
      (*F * x) + (*G * y) + (*H * z),
      // U = (x * T) + (y * G)
      // T = (U - (y * G)) * x^-1
      (*U - (*G * y)) * x.invert().unwrap()
    ));

    xz.push((x, z));
  }

  let statement = ChaumStatement::new(b"Hello, World!".to_vec(), S_T);
  let witness = ChaumWitness::new(statement.clone(), xz);
  assert!(ChaumProof::prove(&mut OsRng, &witness, &y).verify(&statement));
}

#[cfg(feature = "multisig")]
#[test]
fn chaum_multisig() {
  let keys = key_gen::<_, Secp256k1>(&mut OsRng);

  #[allow(non_snake_case)]
  let mut S_T = vec![];
  let mut xz = vec![];
  for _ in 0 .. 2 {
    let x = Scalar::random(&mut OsRng);
    let z = Scalar::random(&mut OsRng);

    S_T.push((
      (*F * x) + keys[&1].group_key() + (*H * z),
      (*U - keys[&1].group_key()) * x.invert().unwrap()
    ));

    xz.push((x, z));
  }

  let statement = ChaumStatement::new(b"Hello, Multisig World!".to_vec(), S_T);
  let witness = ChaumWitness::new(statement.clone(), xz);

  assert!(
    sign(
      &mut OsRng,
      algorithm_machines(
        &mut OsRng,
        ChaumMultisig::new(Transcript::new(b"Firo Serai Chaum Test".to_vec()), witness),
        &keys
      ),
      &[]
    ).verify(&statement)
  );
}
