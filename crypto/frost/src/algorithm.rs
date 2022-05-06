use core::{marker::PhantomData, fmt::Debug};

use rand_core::{RngCore, CryptoRng};

use group::Group;

use transcript::Transcript;

use crate::{Curve, FrostError, MultisigView};

/// Algorithm to use FROST with
pub trait Algorithm<C: Curve>: Clone {
  type Transcript: Transcript + Clone + Debug;
  /// The resulting type of the signatures this algorithm will produce
  type Signature: Clone + Debug;

  fn transcript(&mut self) -> &mut Self::Transcript;

  /// Generate an addendum to FROST"s preprocessing stage
  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &MultisigView<C>,
    nonces: &[C::F; 2],
  ) -> Vec<u8>;

  /// Proccess the addendum for the specified participant. Guaranteed to be ordered
  fn process_addendum(
    &mut self,
    params: &MultisigView<C>,
    l: usize,
    commitments: &[C::G; 2],
    serialized: &[u8],
  ) -> Result<(), FrostError>;

  /// Sign a share with the given secret/nonce
  /// The secret will already have been its lagrange coefficient applied so it is the necessary
  /// key share
  /// The nonce will already have been processed into the combined form d + (e * p)
  fn sign_share(
    &mut self,
    params: &MultisigView<C>,
    nonce_sum: C::G,
    binding: C::F,
    nonce: C::F,
    msg: &[u8],
  ) -> C::F;

  /// Verify a signature
  fn verify(&self, group_key: C::G, nonce: C::G, sum: C::F) -> Option<Self::Signature>;

  /// Verify a specific share given as a response. Used to determine blame if signature
  /// verification fails
  fn verify_share(
    &self,
    verification_share: C::G,
    nonce: C::G,
    share: C::F,
  ) -> bool;
}

// Transcript which will create an IETF compliant serialization for the binding factor
#[derive(Clone, Debug)]
pub struct IetfTranscript(Vec<u8>);
impl Transcript for IetfTranscript {
  fn domain_separate(&mut self, _: &[u8]) {}

  fn append_message(&mut self, _: &'static [u8], message: &[u8]) {
    self.0.extend(message);
  }

  fn challenge(&mut self, _: &'static [u8]) -> Vec<u8> {
    self.0.clone()
  }

  fn rng_seed(&mut self, _: &'static [u8], _: Option<[u8; 32]>) -> [u8; 32] {
    unimplemented!()
  }
}


pub trait Hram<C: Curve>: Clone {
  /// HRAM function to generate a challenge
  /// H2 from the IETF draft despite having a different argument set (not pre-formatted)
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F;
}

#[derive(Clone)]
pub struct Schnorr<C: Curve, H: Hram<C>> {
  transcript: IetfTranscript,
  c: Option<C::F>,
  _hram: PhantomData<H>,
}

impl<C: Curve, H: Hram<C>> Schnorr<C, H> {
  pub fn new() -> Schnorr<C, H> {
    Schnorr {
      transcript: IetfTranscript(vec![]),
      c: None,
      _hram: PhantomData
    }
  }
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchnorrSignature<C: Curve> {
  pub R: C::G,
  pub s: C::F,
}

/// Implementation of Schnorr signatures for use with FROST
impl<C: Curve, H: Hram<C>> Algorithm<C> for Schnorr<C, H> {
  type Transcript = IetfTranscript;
  type Signature = SchnorrSignature<C>;

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    _: &mut R,
    _: &MultisigView<C>,
    _: &[C::F; 2],
  ) -> Vec<u8> {
    vec![]
  }

  fn process_addendum(
    &mut self,
    _: &MultisigView<C>,
    _: usize,
    _: &[C::G; 2],
    _: &[u8],
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &MultisigView<C>,
    nonce_sum: C::G,
    _: C::F,
    nonce: C::F,
    msg: &[u8],
  ) -> C::F {
    let c = H::hram(&nonce_sum, &params.group_key(), msg);
    self.c = Some(c);

    nonce + (params.secret_share() * c)
  }

  fn verify(&self, group_key: C::G, nonce: C::G, sum: C::F) -> Option<Self::Signature> {
    if (C::generator_table() * sum) + (C::G::identity() - (group_key * self.c.unwrap())) == nonce {
      Some(SchnorrSignature { R: nonce, s: sum })
    } else {
      None
    }
  }

  fn verify_share(
    &self,
    verification_share: C::G,
    nonce: C::G,
    share: C::F,
  ) -> bool {
    (C::generator_table() * share) == (nonce + (verification_share * self.c.unwrap()))
  }
}
