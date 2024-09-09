use std::{
  collections::HashMap,
  io::{self, Read},
};

use rand_core::{RngCore, CryptoRng};

use ciphersuite::Ristretto;
use frost::{
  dkg::{Participant, ThresholdKeys},
  FrostError,
  algorithm::Algorithm,
  sign::*,
};
use frost_schnorrkel::Schnorrkel;

// This wraps a Schnorrkel sign machine into one with a preset message.
#[derive(Clone)]
pub(crate) struct WrappedSchnorrkelMachine(ThresholdKeys<Ristretto>, Vec<u8>);
impl WrappedSchnorrkelMachine {
  pub(crate) fn new(keys: ThresholdKeys<Ristretto>, msg: Vec<u8>) -> Self {
    Self(keys, msg)
  }
}

pub(crate) struct WrappedSchnorrkelSignMachine(
  <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::SignMachine,
  Vec<u8>,
);

type Signature = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Signature;
impl PreprocessMachine for WrappedSchnorrkelMachine {
  type Preprocess = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Preprocess;
  type Signature = Signature;
  type SignMachine = WrappedSchnorrkelSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Preprocess<Ristretto, <Schnorrkel as Algorithm<Ristretto>>::Addendum>)
  {
    let WrappedSchnorrkelMachine(keys, batch) = self;
    let (machine, preprocess) =
      AlgorithmMachine::new(Schnorrkel::new(b"substrate"), keys).preprocess(rng);
    (WrappedSchnorrkelSignMachine(machine, batch), preprocess)
  }
}

impl SignMachine<Signature> for WrappedSchnorrkelSignMachine {
  type Params = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<Signature>>::Params;
  type Keys = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<Signature>>::Keys;
  type Preprocess =
    <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<Signature>>::Preprocess;
  type SignatureShare =
    <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<Signature>>::SignatureShare;
  type SignatureMachine =
    <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<Signature>>::SignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!()
  }

  fn from_cache(
    _algorithm: Schnorrkel,
    _keys: ThresholdKeys<Ristretto>,
    _cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!()
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.0.read_preprocess(reader)
  }

  fn sign(
    self,
    preprocesses: HashMap<
      Participant,
      Preprocess<Ristretto, <Schnorrkel as Algorithm<Ristretto>>::Addendum>,
    >,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, SignatureShare<Ristretto>), FrostError> {
    assert!(msg.is_empty());
    self.0.sign(preprocesses, &self.1)
  }
}
