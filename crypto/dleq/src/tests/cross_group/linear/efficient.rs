use rand_core::{RngCore, OsRng};

use ff::Field;

use k256::Scalar;
#[cfg(feature = "serialize")]
use k256::ProjectivePoint;
#[cfg(feature = "serialize")]
use dalek_ff_group::EdwardsPoint;

use blake2::{Digest, Blake2b512};

use crate::{
  cross_group::linear::EfficientDLEq,
  tests::cross_group::{transcript, generators}
};

#[test]
fn test_linear_efficient_cross_group_dleq() {
  let generators = generators();

  for i in 0 .. 1 {
    let (proof, keys) = if i == 0 {
      let mut seed = [0; 32];
      OsRng.fill_bytes(&mut seed);

      EfficientDLEq::prove(
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
        res = EfficientDLEq::prove_without_bias(
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
      let deserialized = EfficientDLEq::<ProjectivePoint, EdwardsPoint>::deserialize(
        &mut std::io::Cursor::new(&buf)
      ).unwrap();
      assert_eq!(proof, deserialized);
      deserialized.verify(&mut OsRng, &mut transcript(), generators).unwrap();
    }
  }
}
