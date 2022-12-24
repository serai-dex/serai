use core::ops::Deref;

use hex_literal::hex;

use rand_core::OsRng;

use zeroize::Zeroizing;

use ff::Field;
use group::GroupEncoding;

use k256::{Scalar, ProjectivePoint};

use transcript::{Transcript, RecommendedTranscript};

use crate::DLEqProof;

#[cfg(feature = "experimental")]
mod cross_group;

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

  for i in 0 .. 5 {
    let key = Zeroizing::new(Scalar::random(&mut OsRng));
    let proof = DLEqProof::prove(&mut OsRng, &mut transcript(), &generators[.. i], &key);

    let mut keys = [ProjectivePoint::GENERATOR; 5];
    for k in 0 .. 5 {
      keys[k] = generators[k] * key.deref();
    }
    proof.verify(&mut transcript(), &generators[.. i], &keys[.. i]).unwrap();
    // Different challenge
    assert!(proof
      .verify(
        &mut RecommendedTranscript::new(b"different challenge"),
        &generators[.. i],
        &keys[.. i]
      )
      .is_err());

    // We could edit these tests to always test with at least two generators
    // Then we don't test proofs with zero/one generator(s)
    // While those are stupid, and pointless, and potentially point to a failure in the caller,
    // it could also be part of a dynamic system which deals with variable amounts of generators
    // Not panicking in such use cases, even if they're inefficient, provides seamless behavior
    if i >= 2 {
      // Different generators
      assert!(proof
        .verify(
          &mut transcript(),
          generators[.. i].iter().cloned().rev().collect::<Vec<_>>().as_ref(),
          &keys[.. i]
        )
        .is_err());
      // Different keys
      assert!(proof
        .verify(
          &mut transcript(),
          &generators[.. i],
          keys[.. i].iter().cloned().rev().collect::<Vec<_>>().as_ref()
        )
        .is_err());
    }

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
