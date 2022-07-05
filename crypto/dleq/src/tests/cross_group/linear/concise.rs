use rand_core::{RngCore, OsRng};

use ff::{Field, PrimeField};

use k256::Scalar;
#[cfg(feature = "serialize")]
use k256::ProjectivePoint;
#[cfg(feature = "serialize")]
use dalek_ff_group::EdwardsPoint;

use blake2::{Digest, Blake2b512};

use crate::{
  cross_group::{scalar::mutual_scalar_from_bytes, linear::ConciseDLEq},
  tests::cross_group::{transcript, generators}
};

#[test]
fn test_linear_concise_cross_group_dleq() {
  let generators = generators();

  for i in 0 .. 1 {
    let (proof, keys) = if i == 0 {
      let mut seed = [0; 32];
      OsRng.fill_bytes(&mut seed);

      ConciseDLEq::prove(
        &mut OsRng,
        &mut transcript(),
        generators,
        Blake2b512::new().chain_update(seed)
      )
    } else {
      let mut key;
      let mut res;
      while {
        key = Scalar::random(&mut OsRng);
        res = ConciseDLEq::prove_without_bias(
          &mut OsRng,
          &mut transcript(),
          generators,
          key
        );
        res.is_none()
      } {}
      let res = res.unwrap();
      assert_eq!(key, res.1.0);
      res
    };

    let public_keys = proof.verify(&mut OsRng, &mut transcript(), generators).unwrap();
    assert_eq!(generators.0.primary * keys.0, public_keys.0);
    assert_eq!(generators.1.primary * keys.1, public_keys.1);

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      proof.serialize(&mut buf).unwrap();
      let deserialized = ConciseDLEq::<ProjectivePoint, EdwardsPoint>::deserialize(
        &mut std::io::Cursor::new(&buf)
      ).unwrap();
      assert_eq!(proof, deserialized);
      deserialized.verify(&mut OsRng, &mut transcript(), generators).unwrap();
    }
  }
}

#[test]
fn test_remainder() {
  // Uses Secp256k1 for both to achieve an odd capacity of 255
  assert_eq!(Scalar::CAPACITY, 255);
  let generators = (generators().0, generators().0);
  let keys = mutual_scalar_from_bytes(&[0xFF; 32]);
  assert_eq!(keys.0, keys.1);

  let (proof, res) = ConciseDLEq::prove_without_bias(
    &mut OsRng,
    &mut transcript(),
    generators,
    keys.0
  ).unwrap();
  assert_eq!(keys, res);

  let public_keys = proof.verify(&mut OsRng, &mut transcript(), generators).unwrap();
  assert_eq!(generators.0.primary * keys.0, public_keys.0);
  assert_eq!(generators.1.primary * keys.1, public_keys.1);

  #[cfg(feature = "serialize")]
  {
    let mut buf = vec![];
    proof.serialize(&mut buf).unwrap();
    let deserialized = ConciseDLEq::<ProjectivePoint, ProjectivePoint>::deserialize(
      &mut std::io::Cursor::new(&buf)
    ).unwrap();
    assert_eq!(proof, deserialized);
    deserialized.verify(&mut OsRng, &mut transcript(), generators).unwrap();
  }
}
