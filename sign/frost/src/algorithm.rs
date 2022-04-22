use core::{marker::PhantomData, fmt::Debug};

use rand_core::{RngCore, CryptoRng};
use digest::Digest;

use group::Group;

use crate::{Curve, FrostError, sign};

pub trait Algorithm<C: Curve>: Clone + Debug {
  /// The resulting type of the signatures this algorithm will produce
  type Signature: Clone + Debug;

  /// Context for this algorithm to be hashed into b, and therefore committed to
  fn context(&self) -> Vec<u8>;

  /// The amount of bytes from each participant's addendum to commit to
  fn addendum_commit_len() -> usize;

  /// Generate an addendum to FROST"s preprocessing stage
  fn preprocess_addendum<R: RngCore + CryptoRng>(
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
    p: &C::F,
    serialized: &[u8],
  ) -> Result<(), FrostError>;

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

pub trait Hram: PartialEq + Eq + Copy + Clone + Debug {
  #[allow(non_snake_case)]
  fn hram<C: Curve>(R: &C::G, A: &C::G, m: &[u8]) -> C::F;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blake2bHram {}
impl Hram for Blake2bHram {
  #[allow(non_snake_case)]
  fn hram<C: Curve>(R: &C::G, A: &C::G, m: &[u8]) -> C::F {
    C::F_from_bytes_wide(
      blake2::Blake2b::new()
        .chain(C::G_to_bytes(R))
        .chain(C::G_to_bytes(A))
        .chain(m)
        .finalize()
        .as_slice()
        .try_into()
        .expect("couldn't convert a 64-byte hash to a 64-byte array")
    )
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Schnorr<C: Curve, H: Hram> {
  c: Option<C::F>,
  hram: PhantomData<H>,
}

impl<C: Curve, H: Hram> Schnorr<C, H> {
  pub fn new() -> Schnorr<C, H> {
    Schnorr {
      c: None,
      hram: PhantomData
    }
  }
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchnorrSignature<C: Curve> {
  pub R: C::G,
  pub s: C::F,
}

impl<C: Curve, H: Hram> Algorithm<C> for Schnorr<C, H> {
  type Signature = SchnorrSignature<C>;

  fn context(&self) -> Vec<u8> {
    vec![]
  }

  fn addendum_commit_len() -> usize {
    0
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
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
    _: &C::F,
    _: &[u8],
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &sign::ParamsView<C>,
    nonce_sum: C::G,
    nonce: C::F,
    msg: &[u8],
  ) -> C::F {
    let c = H::hram::<C>(&nonce_sum, &params.group_key(), msg);
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
