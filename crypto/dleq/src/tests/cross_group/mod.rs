mod scalar;
mod schnorr;

use hex_literal::hex;
use rand_core::OsRng;

use ff::Field;
use group::{Group, GroupEncoding};

use k256::{Scalar, ProjectivePoint};
use dalek_ff_group::{EdwardsPoint, CompressedEdwardsY};

use transcript::RecommendedTranscript;

use crate::{Generators, cross_group::DLEqProof};

#[test]
fn test_dleq() {
  let transcript = || RecommendedTranscript::new(b"Cross-Group DLEq Proof Test");

  let generators = (
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
  );

  let key = Scalar::random(&mut OsRng);
  let (proof, keys) = DLEqProof::prove(&mut OsRng, &mut transcript(), generators, key);

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
