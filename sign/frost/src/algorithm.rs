use core::{marker::PhantomData, fmt::Debug};

use rand_core::{RngCore, CryptoRng};

use group::Group;

use crate::{Curve, FrostError, sign};

/// Algorithm to use FROST with
pub trait Algorithm<C: Curve>: Clone {
  /// The resulting type of the signatures this algorithm will produce
  type Signature: Clone + Debug;

  /// The amount of bytes from each participant's addendum to commit to
  fn addendum_commit_len() -> usize;

  /// Generate an addendum to FROST"s preprocessing stage
  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    params: &sign::ParamsView<C>,
    nonces: &[C::F; 2],
  ) -> Vec<u8>;

  /// Proccess the addendum for the specified participant. Guaranteed to be ordered
  fn process_addendum(
    &mut self,
    params: &sign::ParamsView<C>,
    l: usize,
    commitments: &[C::G; 2],
    serialized: &[u8],
  ) -> Result<(), FrostError>;

  /// Context for this algorithm to be hashed into b, and therefore committed to
  fn context(&self) -> Vec<u8>;

  /// Process the binding factor generated from all the committed to data
  fn process_binding(&mut self, p: &C::F);

  /// Sign a share with the given secret/nonce
  /// The secret will already have been its lagrange coefficient applied so it is the necessary
  /// key share
  /// The nonce will already have been processed into the combined form d + (e * p)
  fn sign_share(
    &mut self,
    params: &sign::ParamsView<C>,
    nonce_sum: C::G,
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

pub trait Hram<C: Curve>: Clone {
  /// HRAM function to generate a challenge
  /// H2 from the IETF draft despite having a different argument set (not pre-formatted)
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F;
}

#[derive(Clone)]
pub struct Schnorr<C: Curve, H: Hram<C>> {
  c: Option<C::F>,
  _hram: PhantomData<H>,
}

impl<C: Curve, H: Hram<C>> Schnorr<C, H> {
  pub fn new() -> Schnorr<C, H> {
    Schnorr {
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
  type Signature = SchnorrSignature<C>;

  fn addendum_commit_len() -> usize {
    0
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _: &mut R,
    _: &sign::ParamsView<C>,
    _: &[C::F; 2],
  ) -> Vec<u8> {
    vec![]
  }

  fn process_addendum(
    &mut self,
    _: &sign::ParamsView<C>,
    _: usize,
    _: &[C::G; 2],
    _: &[u8],
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn context(&self) -> Vec<u8> {
    vec![]
  }

  fn process_binding(&mut self, _: &C::F) {}

  fn sign_share(
    &mut self,
    params: &sign::ParamsView<C>,
    nonce_sum: C::G,
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
