#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use std_shims::{
  vec::Vec,
  io::{self, Read},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroizing;

use transcript::{Transcript as _, MerlinTranscript};

use ciphersuite::{
  group::{ff::PrimeField as _, GroupEncoding as _},
  WrappedGroup,
};
use schnorr::SchnorrSignature;

pub use ::frost::*;
use ::frost::{
  algorithm::{Hram, Algorithm, Schnorr},
  curve::Ristretto,
};

use schnorrkel::{
  PublicKey, Signature,
  context::{SigningTranscript as _, SigningContext},
};

type RistrettoPoint = <Ristretto as WrappedGroup>::G;
type Scalar = <Ristretto as WrappedGroup>::F;

#[derive(Clone)]
struct SchnorrkelHram;
impl Hram<Ristretto> for SchnorrkelHram {
  #[expect(non_snake_case)]
  fn hram(R: &RistrettoPoint, A: &RistrettoPoint, m: &[u8]) -> Scalar {
    let ctx_len =
      usize::try_from(u32::from_le_bytes(m[0 .. 4].try_into().expect("malformed message")))
        .unwrap();

    let mut t = SigningContext::new(&m[4 .. (4 + ctx_len)]).bytes(&m[(4 + ctx_len) ..]);
    t.proto_name(b"Schnorr-sig");
    let convert =
      |point: &RistrettoPoint| PublicKey::from_bytes(&point.to_bytes()).unwrap().into_compressed();
    t.commit_point(b"sign:pk", &convert(A));
    t.commit_point(b"sign:R", &convert(R));
    Scalar::from_repr(t.challenge_scalar(b"sign:c").to_bytes()).unwrap()
  }
}

/// FROST Schnorrkel algorithm.
#[derive(Clone)]
pub struct Schnorrkel {
  context: &'static [u8],
  schnorr: Schnorr<Ristretto, MerlinTranscript, SchnorrkelHram>,
  signing_context: Option<merlin::Transcript>,
}

impl Schnorrkel {
  /// Create a new algorithm with the specified context.
  ///
  /// If the context is greater than or equal to 4 GB in size, this will panic.
  pub fn new(context: &'static [u8]) -> Schnorrkel {
    let mut transcript = MerlinTranscript::new(b"frost-schnorrkel");
    transcript.domain_separate(context);
    Schnorrkel { context, schnorr: Schnorr::new(transcript), signing_context: None }
  }
}

impl Algorithm<Ristretto> for Schnorrkel {
  type Transcript = MerlinTranscript;
  type Addendum = ();
  type Signature = Signature;

  fn transcript(&mut self) -> &mut Self::Transcript {
    self.schnorr.transcript()
  }

  fn nonces(&self) -> Vec<Vec<<Ristretto as WrappedGroup>::G>> {
    self.schnorr.nonces()
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _: &mut R,
    _: &ThresholdKeys<Ristretto>,
  ) {
  }

  fn read_addendum<R: Read>(&self, _: &mut R) -> io::Result<Self::Addendum> {
    Ok(())
  }

  fn process_addendum(
    &mut self,
    _: &ThresholdView<Ristretto>,
    _: Participant,
    (): (),
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &ThresholdView<Ristretto>,
    nonce_sums: &[Vec<RistrettoPoint>],
    nonces: Vec<Zeroizing<Scalar>>,
    msg: &[u8],
  ) -> Scalar {
    self.signing_context = Some(SigningContext::new(self.context).bytes(msg));
    self.schnorr.sign_share(
      params,
      nonce_sums,
      nonces,
      &[
        &u32::try_from(self.context.len()).expect("context exceeded 2^32 bytes").to_le_bytes(),
        self.context,
        msg,
      ]
      .concat(),
    )
  }

  fn verify(
    &self,
    group_key: RistrettoPoint,
    nonces: &[Vec<RistrettoPoint>],
    sum: Scalar,
  ) -> Option<Self::Signature> {
    let mut signature = (SchnorrSignature::<Ristretto> { R: nonces[0][0], s: sum }).serialize();
    signature[63] |= 1 << 7;
    let signature = Signature::from_bytes(&signature).unwrap();

    PublicKey::from_bytes(&group_key.to_bytes())
      .unwrap()
      .verify(self.signing_context.as_ref()?.clone(), &signature)
      .is_ok()
      .then_some(signature)
  }

  fn verify_share(
    &self,
    verification_share: RistrettoPoint,
    nonces: &[Vec<RistrettoPoint>],
    share: Scalar,
  ) -> Result<Vec<(Scalar, RistrettoPoint)>, ()> {
    self.schnorr.verify_share(verification_share, nonces, share)
  }
}

#[test]
fn test() {
  use rand_core::OsRng;

  use frost::tests::{key_gen, algorithm_machines, sign};

  const CONTEXT: &[u8] = b"FROST Schnorrkel Test";
  const MSG: &[u8] = b"Hello, World!";

  let keys = key_gen(&mut OsRng);
  let key = keys[&Participant::new(1).unwrap()].group_key();
  let algorithm = Schnorrkel::new(CONTEXT);
  let machines = algorithm_machines(&mut OsRng, &algorithm, &keys);
  let signature = sign(&mut OsRng, &algorithm, keys, machines, MSG);

  let key = PublicKey::from_bytes(key.to_bytes().as_ref()).unwrap();
  key.verify(SigningContext::new(CONTEXT).bytes(MSG), &signature).unwrap();
}
