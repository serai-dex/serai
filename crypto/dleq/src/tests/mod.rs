#[cfg(feature = "experimental")]
mod cross_group;

use hex_literal::hex;
use rand_core::OsRng;

use ff::Field;
use group::GroupEncoding;

use k256::{Scalar, ProjectivePoint};

use transcript::{Transcript, RecommendedTranscript};

use crate::DLEqProof;

#[test]
fn test_dleq() {
  let transcript = || RecommendedTranscript::new(b"DLEq Proof Test");

  let generators = [
    ProjectivePoint::GENERATOR,
    ProjectivePoint::from_bytes(
      &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into()),
    )
    .unwrap(),
    // Just an increment of the last byte from the previous, where the previous two are valid
    ProjectivePoint::from_bytes(
      &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac4").into()),
    )
    .unwrap(),
    ProjectivePoint::from_bytes(
      &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803aca").into()),
    )
    .unwrap(),
    ProjectivePoint::from_bytes(
      &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803acb").into()),
    )
    .unwrap(),
  ];

  for i in 0..5 {
    let key = Scalar::random(&mut OsRng);
    let proof = DLEqProof::prove(&mut OsRng, &mut transcript(), &generators[..i], key);

    let mut keys = [ProjectivePoint::GENERATOR; 5];
    for k in 0..5 {
      keys[k] = generators[k] * key;
    }
    proof.verify(&mut transcript(), &generators[..i], &keys[..i]).unwrap();

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      proof.serialize(&mut buf).unwrap();
      let deserialized =
        DLEqProof::<ProjectivePoint>::deserialize(&mut std::io::Cursor::new(&buf)).unwrap();
      assert_eq!(proof, deserialized);
    }
  }
}
