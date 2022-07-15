use rand_core::OsRng;

use group::{ff::Field, Group};

use multiexp::BatchVerifier;

use crate::{
  cross_group::aos::{Re, Aos},
  tests::cross_group::{G0, G1, transcript, generators},
};

#[allow(non_snake_case)]
#[cfg(feature = "serialize")]
fn test_aos_serialization<const RING_LEN: usize>(proof: Aos<G0, G1, RING_LEN>, Re_0: Re<G0, G1>) {
  let mut buf = vec![];
  proof.serialize(&mut buf).unwrap();
  let deserialized = Aos::deserialize(&mut std::io::Cursor::new(buf), Re_0).unwrap();
  assert_eq!(proof, deserialized);
}

fn test_aos<const RING_LEN: usize>(default: Re<G0, G1>) {
  let generators = generators();

  let mut ring_keys = [(<G0 as Group>::Scalar::zero(), <G1 as Group>::Scalar::zero()); RING_LEN];
  // Side-effect of G0 being a type-alias with identity() deprecated
  #[allow(deprecated)]
  let mut ring = [(G0::identity(), G1::identity()); RING_LEN];
  for i in 0 .. RING_LEN {
    ring_keys[i] =
      (<G0 as Group>::Scalar::random(&mut OsRng), <G1 as Group>::Scalar::random(&mut OsRng));
    ring[i] = (generators.0.alt * ring_keys[i].0, generators.1.alt * ring_keys[i].1);
  }

  for actual in 0 .. RING_LEN {
    let proof = Aos::<_, _, RING_LEN>::prove(
      &mut OsRng,
      transcript(),
      generators,
      &ring,
      actual,
      ring_keys[actual],
      default.clone(),
    );

    let mut batch = (BatchVerifier::new(0), BatchVerifier::new(0));
    proof.verify(&mut OsRng, transcript(), generators, &mut batch, &ring).unwrap();
    // For e, these should have nothing. For R, these should have 6 elements each which sum to 0
    assert!(batch.0.verify_vartime());
    assert!(batch.1.verify_vartime());

    #[cfg(feature = "serialize")]
    test_aos_serialization(proof, default.clone());
  }
}

#[test]
fn test_aos_e() {
  test_aos::<2>(Re::e_default());
  test_aos::<4>(Re::e_default());
}

#[allow(non_snake_case)]
#[test]
fn test_aos_R() {
  // Batch verification appreciates the longer vectors, which means not batching bits
  test_aos::<2>(Re::R_default());
}
