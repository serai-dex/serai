use core::ops::Deref;

use hex_literal::hex;

use rand_core::OsRng;

use zeroize::Zeroizing;

use ff::Field;
use group::GroupEncoding;

use k256::{Scalar, ProjectivePoint};

use transcript::{Transcript, RecommendedTranscript};

use crate::{DLEqProof, MultiDLEqProof};

#[cfg(feature = "experimental")]
mod cross_group;

fn generators() -> [k256::ProjectivePoint; 5] {
  [
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
  ]
}

#[test]
fn test_dleq() {
  let generators = generators();
  let transcript = || RecommendedTranscript::new(b"DLEq Proof Test");

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

    // All of these following tests should effectively be a different challenge and accordingly
    // pointless. They're still nice to have though

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
          generators[.. i].iter().copied().rev().collect::<Vec<_>>().as_ref(),
          &keys[.. i]
        )
        .is_err());
      // Different keys
      assert!(proof
        .verify(
          &mut transcript(),
          &generators[.. i],
          keys[.. i].iter().copied().rev().collect::<Vec<_>>().as_ref()
        )
        .is_err());
    }

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      proof.write(&mut buf).unwrap();
      let deserialized = DLEqProof::<ProjectivePoint>::read::<&[u8]>(&mut buf.as_ref()).unwrap();
      assert_eq!(proof, deserialized);
    }
  }
}

#[test]
fn test_multi_dleq() {
  let generators = generators();
  let transcript = || RecommendedTranscript::new(b"MultiDLEq Proof Test");

  // Test up to 3 keys
  for k in 0 ..= 3 {
    let mut keys = vec![];
    let mut these_generators = vec![];
    let mut pub_keys = vec![];
    for i in 0 .. k {
      let key = Zeroizing::new(Scalar::random(&mut OsRng));
      // For each key, test a variable set of generators
      // 0: 0
      // 1: 1, 2
      // 2: 2, 3, 4
      let key_generators = generators[i .. (i + i + 1)].to_vec();
      let mut these_pub_keys = vec![];
      for generator in &key_generators {
        these_pub_keys.push(generator * key.deref());
      }
      keys.push(key);
      these_generators.push(key_generators);
      pub_keys.push(these_pub_keys);
    }

    let proof = MultiDLEqProof::prove(&mut OsRng, &mut transcript(), &these_generators, &keys);

    proof.verify(&mut transcript(), &these_generators, &pub_keys).unwrap();
    // Different challenge
    assert!(proof
      .verify(&mut RecommendedTranscript::new(b"different challenge"), &these_generators, &pub_keys)
      .is_err());

    // Test verifying for a different amount of keys fail
    if k > 0 {
      assert!(proof.verify(&mut transcript(), &these_generators, &pub_keys[.. k - 1]).is_err());
    }

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      proof.write(&mut buf).unwrap();
      let deserialized =
        MultiDLEqProof::<ProjectivePoint>::read::<&[u8]>(&mut buf.as_ref(), k).unwrap();
      assert_eq!(proof, deserialized);
    }
  }
}
