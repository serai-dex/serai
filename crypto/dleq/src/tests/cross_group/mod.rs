mod scalar;
mod schnorr;

use hex_literal::hex;
use rand_core::OsRng;

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use k256::{Scalar, ProjectivePoint};
use dalek_ff_group::{self as dfg, EdwardsPoint, CompressedEdwardsY};

use transcript::RecommendedTranscript;

use crate::{Generators, cross_group::linear::EfficientDLEq};

mod linear;

pub(crate) fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"Cross-Group DLEq Proof Test")
}

pub(crate) fn generators() -> (Generators<ProjectivePoint>, Generators<EdwardsPoint>) {
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
    EfficientDLEq::prove_without_bias(
      &mut OsRng,
      &mut RecommendedTranscript::new(b""),
      generators(),
      pow_2
    ).is_none()
  );
}
