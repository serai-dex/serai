use transcript::Transcript;
use ciphersuite::{group::GroupEncoding, Ciphersuite};

mod sealed {
  use super::*;

  /// Derive challenge scalars through some arbitrary process from a challenge.
  pub trait Challenger<T: 'static + Transcript, C: Ciphersuite>:
    Fn(T::Challenge) -> Vec<C::F>
  {
  }
  impl<T: 'static + Transcript, C: Ciphersuite, F: Fn(T::Challenge) -> Vec<C::F>> Challenger<T, C>
    for F
  {
  }

  /// Transform a challenge as needed by a specified weight.
  pub trait ChallengeApplicator<C: Ciphersuite>: Fn(&[C::F]) -> C::F {}
  impl<C: Ciphersuite, F: Fn(&[C::F]) -> C::F> ChallengeApplicator<C> for F {}
}
pub(crate) use sealed::*;

// TODO: Take in a transcript
pub(crate) fn commitment_challenge<T: 'static + Transcript, C: Ciphersuite>(
  commitment: C::G,
) -> T::Challenge {
  let mut transcript = T::new(b"Bulletproofs+ Commitment Challenge");
  transcript.append_message(b"commitment", commitment.to_bytes());
  transcript.challenge(b"challenge")
}
