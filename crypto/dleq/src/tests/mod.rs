#[cfg(feature = "experimental_cross_group")]
mod cross_group;

use hex_literal::hex;
use rand_core::OsRng;

use ff::Field;
use group::GroupEncoding;

use k256::{Scalar, ProjectivePoint};

use transcript::RecommendedTranscript;

use crate::{Generators, DLEqProof};

#[test]
fn test_dleq() {
  let transcript = || RecommendedTranscript::new(b"DLEq Proof Test");

  let generators = Generators::new(
    ProjectivePoint::GENERATOR,
    ProjectivePoint::from_bytes(
      &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into())
    ).unwrap()
  );

  let key = Scalar::random(&mut OsRng);
  let proof = DLEqProof::prove(&mut OsRng, &mut transcript(), generators, key);

  let keys = (generators.primary * key, generators.alt * key);
  proof.verify(&mut transcript(), generators, keys).unwrap();

  #[cfg(feature = "serialize")]
  {
    let mut buf = vec![];
    proof.serialize(&mut buf).unwrap();
    let deserialized = DLEqProof::<ProjectivePoint>::deserialize(
      &mut std::io::Cursor::new(&buf)
    ).unwrap();
    assert_eq!(proof, deserialized);
    deserialized.verify(&mut transcript(), generators, keys).unwrap();
  }
}
