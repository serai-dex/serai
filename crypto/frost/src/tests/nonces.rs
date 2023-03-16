use std::io::{self, Read};

use zeroize::Zeroizing;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::group::{ff::Field, Group, GroupEncoding};

use dleq::MultiDLEqProof;
pub use dkg::tests::{key_gen, recover_key};

use crate::{
  Curve, Participant, ThresholdView, ThresholdKeys, FrostError,
  algorithm::Algorithm,
  sign::{Writable, SignMachine},
  tests::{algorithm_machines, preprocess, sign},
};

#[derive(Clone)]
struct MultiNonce<C: Curve> {
  transcript: RecommendedTranscript,
  nonces: Option<Vec<Vec<C::G>>>,
}

impl<C: Curve> MultiNonce<C> {
  fn new() -> MultiNonce<C> {
    MultiNonce {
      transcript: RecommendedTranscript::new(b"FROST MultiNonce Algorithm Test"),
      nonces: None,
    }
  }
}

fn nonces<C: Curve>() -> Vec<Vec<C::G>> {
  vec![
    vec![C::generator(), C::generator().double()],
    vec![C::generator(), C::generator() * C::F::from(3), C::generator() * C::F::from(4)],
  ]
}

fn verify_nonces<C: Curve>(nonces: &[Vec<C::G>]) {
  assert_eq!(nonces.len(), 2);

  // Each nonce should be a series of commitments, over some generators, which share a discrete log
  // Since they share a discrete log, their only distinction should be the generator
  // Above, the generators were created with a known relationship
  // Accordingly, we can check here that relationship holds to make sure these commitments are well
  // formed
  assert_eq!(nonces[0].len(), 2);
  assert_eq!(nonces[0][0].double(), nonces[0][1]);

  assert_eq!(nonces[1].len(), 3);
  assert_eq!(nonces[1][0] * C::F::from(3), nonces[1][1]);
  assert_eq!(nonces[1][0] * C::F::from(4), nonces[1][2]);

  assert!(nonces[0][0] != nonces[1][0]);
}

impl<C: Curve> Algorithm<C> for MultiNonce<C> {
  type Transcript = RecommendedTranscript;
  type Addendum = ();
  type Signature = ();

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn nonces(&self) -> Vec<Vec<C::G>> {
    nonces::<C>()
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(&mut self, _: &mut R, _: &ThresholdKeys<C>) {}

  fn read_addendum<R: Read>(&self, _: &mut R) -> io::Result<Self::Addendum> {
    Ok(())
  }

  fn process_addendum(
    &mut self,
    _: &ThresholdView<C>,
    _: Participant,
    _: (),
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    _: &ThresholdView<C>,
    nonce_sums: &[Vec<C::G>],
    nonces: Vec<Zeroizing<C::F>>,
    _: &[u8],
  ) -> C::F {
    // Verify the nonce sums are as expected
    verify_nonces::<C>(nonce_sums);

    // Verify we actually have two nonces and that they're distinct
    assert_eq!(nonces.len(), 2);
    assert!(nonces[0] != nonces[1]);

    // Save the nonce sums for later so we can check they're consistent with the call to verify
    assert!(self.nonces.is_none());
    self.nonces = Some(nonce_sums.to_vec());

    // Sum the nonces so we can later check they actually have a relationship to nonce_sums
    let mut res = C::F::zero();

    // Weight each nonce
    // This is probably overkill, since their unweighted forms would practically still require
    // some level of crafting to pass a naive sum via malleability, yet this makes it more robust
    for nonce in nonce_sums {
      self.transcript.domain_separate(b"nonce");
      for commitment in nonce {
        self.transcript.append_message(b"commitment", commitment.to_bytes());
      }
    }
    let mut rng = ChaCha20Rng::from_seed(self.transcript.clone().rng_seed(b"weight"));

    for nonce in nonces {
      res += *nonce * C::F::random(&mut rng);
    }
    res
  }

  #[must_use]
  fn verify(&self, _: C::G, nonces: &[Vec<C::G>], sum: C::F) -> Option<Self::Signature> {
    verify_nonces::<C>(nonces);
    assert_eq!(&self.nonces.clone().unwrap(), nonces);

    // Make sure the nonce sums actually relate to the nonces
    let mut res = C::G::identity();
    let mut rng = ChaCha20Rng::from_seed(self.transcript.clone().rng_seed(b"weight"));
    for nonce in nonces {
      res += nonce[0] * C::F::random(&mut rng);
    }
    assert_eq!(res, C::generator() * sum);

    Some(())
  }

  fn verify_share(&self, _: C::G, _: &[Vec<C::G>], _: C::F) -> Result<Vec<(C::F, C::G)>, ()> {
    panic!("share verification triggered");
  }
}

/// Test a multi-nonce, multi-generator algorithm.
// Specifically verifies this library can:
// 1) Generate multiple nonces
// 2) Provide the group nonces (nonce_sums) across multiple generators, still with the same
//    discrete log
// 3) Provide algorithms with nonces which match the group nonces
pub fn test_multi_nonce<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<R, C>(&mut *rng);
  let machines = algorithm_machines(&mut *rng, MultiNonce::<C>::new(), &keys);
  sign(&mut *rng, MultiNonce::<C>::new(), keys.clone(), machines, &[]);
}

/// Test malleating a commitment for a nonce across generators causes the preprocess to error.
pub fn test_invalid_commitment<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<R, C>(&mut *rng);
  let machines = algorithm_machines(&mut *rng, MultiNonce::<C>::new(), &keys);
  let (machines, mut preprocesses) = preprocess(&mut *rng, machines, |_, _| {});

  // Select a random participant to give an invalid commitment
  let participants = preprocesses.keys().collect::<Vec<_>>();
  let faulty = *participants
    [usize::try_from(rng.next_u64() % u64::try_from(participants.len()).unwrap()).unwrap()];

  // Grab their preprocess
  let mut preprocess = preprocesses.remove(&faulty).unwrap();

  // Mutate one of the commitments
  let nonce =
    preprocess.commitments.nonces.get_mut(usize::try_from(rng.next_u64()).unwrap() % 2).unwrap();
  let generators_len = nonce.generators.len();
  *nonce
    .generators
    .get_mut(usize::try_from(rng.next_u64()).unwrap() % generators_len)
    .unwrap()
    .0
    .get_mut(usize::try_from(rng.next_u64()).unwrap() % 2)
    .unwrap() = C::G::random(&mut *rng);

  // The commitments are validated at time of deserialization (read_preprocess)
  // Accordingly, serialize it and read it again to make sure that errors
  assert!(machines
    .iter()
    .next()
    .unwrap()
    .1
    .read_preprocess::<&[u8]>(&mut preprocess.serialize().as_ref())
    .is_err());
}

/// Test malleating the DLEq proof for a preprocess causes it to error.
pub fn test_invalid_dleq_proof<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let keys = key_gen::<R, C>(&mut *rng);
  let machines = algorithm_machines(&mut *rng, MultiNonce::<C>::new(), &keys);
  let (machines, mut preprocesses) = preprocess(&mut *rng, machines, |_, _| {});

  // Select a random participant to give an invalid DLEq proof
  let participants = preprocesses.keys().collect::<Vec<_>>();
  let faulty = *participants
    [usize::try_from(rng.next_u64() % u64::try_from(participants.len()).unwrap()).unwrap()];

  // Invalidate it by replacing it with a completely different proof
  let dlogs = [Zeroizing::new(C::F::random(&mut *rng)), Zeroizing::new(C::F::random(&mut *rng))];
  let mut preprocess = preprocesses.remove(&faulty).unwrap();
  preprocess.commitments.dleq = Some(MultiDLEqProof::prove(
    &mut *rng,
    &mut RecommendedTranscript::new(b"Invalid DLEq Proof"),
    &nonces::<C>(),
    &dlogs,
  ));

  assert!(machines
    .iter()
    .next()
    .unwrap()
    .1
    .read_preprocess::<&[u8]>(&mut preprocess.serialize().as_ref())
    .is_err());

  // Also test None for a proof will cause an error
  preprocess.commitments.dleq = None;
  assert!(machines
    .iter()
    .next()
    .unwrap()
    .1
    .read_preprocess::<&[u8]>(&mut preprocess.serialize().as_ref())
    .is_err());
}
