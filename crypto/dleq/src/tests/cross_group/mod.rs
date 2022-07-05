mod scalar;
mod schnorr;

use hex_literal::hex;
use rand_core::{RngCore, OsRng};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use k256::{Scalar, ProjectivePoint};
use dalek_ff_group::{self as dfg, EdwardsPoint, CompressedEdwardsY};

use blake2::{Digest, Blake2b512};

use transcript::RecommendedTranscript;

use crate::{Generators, cross_group::{DLEqProof, scalar::mutual_scalar_from_bytes}};

fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"Cross-Group DLEq Proof Test")
}

fn generators() -> (Generators<ProjectivePoint>, Generators<EdwardsPoint>) {
  (
    Generators::new(
      ProjectivePoint::GENERATOR,
      ProjectivePoint::from_bytes(
        &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into())
      ).unwrap()
    ),

    Generators::new(
      EdwardsPoint::generator(),
      CompressedEdwardsY::new(
        hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
      ).decompress().unwrap()
    )
  )
}

#[test]
fn test_rejection_sampling() {
  let mut pow_2 = Scalar::one();
  for _ in 0 .. dfg::Scalar::CAPACITY {
    pow_2 = pow_2.double();
  }

  assert!(
    DLEqProof::prove_without_bias(
      &mut OsRng,
      &mut RecommendedTranscript::new(b""),
      generators(),
      pow_2
    ).is_none()
  );
}

#[test]
fn test_cross_group_dleq() {
  let generators = generators();

  for i in 0 .. 2 {
    let (proof, keys) = if i == 0 {
      let mut seed = [0; 32];
      OsRng.fill_bytes(&mut seed);

      DLEqProof::prove(
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
        res = DLEqProof::prove_without_bias(
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

    let public_keys = proof.verify(&mut transcript(), generators).unwrap();
    assert_eq!(generators.0.primary * keys.0, public_keys.0);
    assert_eq!(generators.1.primary * keys.1, public_keys.1);

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      proof.serialize(&mut buf).unwrap();
      let deserialized = DLEqProof::<ProjectivePoint, EdwardsPoint>::deserialize(
        &mut std::io::Cursor::new(&buf)
      ).unwrap();
      assert_eq!(proof, deserialized);
      deserialized.verify(&mut transcript(), generators).unwrap();
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

  let (proof, res) = DLEqProof::prove_without_bias(
    &mut OsRng,
    &mut transcript(),
    generators,
    keys.0
  ).unwrap();
  assert_eq!(keys, res);

  let public_keys = proof.verify(&mut transcript(), generators).unwrap();
  assert_eq!(generators.0.primary * keys.0, public_keys.0);
  assert_eq!(generators.1.primary * keys.1, public_keys.1);

  #[cfg(feature = "serialize")]
  {
    let mut buf = vec![];
    proof.serialize(&mut buf).unwrap();
    let deserialized = DLEqProof::<ProjectivePoint, ProjectivePoint>::deserialize(
      &mut std::io::Cursor::new(&buf)
    ).unwrap();
    assert_eq!(proof, deserialized);
    deserialized.verify(&mut transcript(), generators).unwrap();
  }
}
