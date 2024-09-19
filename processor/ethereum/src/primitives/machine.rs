use std::{io, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use ciphersuite::{Ciphersuite, Secp256k1};
use frost::{
  dkg::{Participant, ThresholdKeys},
  FrostError,
  algorithm::*,
  sign::*,
};

use ethereum_schnorr::{PublicKey, Signature};

use crate::transaction::{Action, Transaction};

/// The HRAm to use for the Schnorr Solidity library.
///
/// This will panic if the public key being signed for is not representable within the Schnorr
/// Solidity library.
#[derive(Clone, Default, Debug)]
pub struct EthereumHram;
impl Hram<Secp256k1> for EthereumHram {
  #[allow(non_snake_case)]
  fn hram(
    R: &<Secp256k1 as Ciphersuite>::G,
    A: &<Secp256k1 as Ciphersuite>::G,
    m: &[u8],
  ) -> <Secp256k1 as Ciphersuite>::F {
    Signature::challenge(*R, &PublicKey::new(*A).unwrap(), m)
  }
}

/// A clonable machine to sign an action.
///
/// This will panic if the public key being signed with is not representable within the Schnorr
/// Solidity library.
#[derive(Clone)]
pub(crate) struct ClonableTransctionMachine {
  pub(crate) keys: ThresholdKeys<Secp256k1>,
  pub(crate) action: Action,
}

type LiteralAlgorithmMachine = AlgorithmMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;
type LiteralAlgorithmSignMachine =
  AlgorithmSignMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;

pub(crate) struct ActionSignMachine {
  key: PublicKey,
  action: Action,
  machine: LiteralAlgorithmSignMachine,
}

type LiteralAlgorithmSignatureMachine =
  AlgorithmSignatureMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;

pub(crate) struct ActionSignatureMachine {
  key: PublicKey,
  action: Action,
  machine: LiteralAlgorithmSignatureMachine,
}

impl PreprocessMachine for ClonableTransctionMachine {
  type Preprocess = <LiteralAlgorithmMachine as PreprocessMachine>::Preprocess;
  type Signature = Transaction;
  type SignMachine = ActionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    let (machine, preprocess) =
      AlgorithmMachine::new(IetfSchnorr::<Secp256k1, EthereumHram>::ietf(), self.keys.clone())
        .preprocess(rng);
    (
      ActionSignMachine {
        key: PublicKey::new(self.keys.group_key()).expect("signing with non-representable key"),
        action: self.action,
        machine,
      },
      preprocess,
    )
  }
}

impl SignMachine<Transaction> for ActionSignMachine {
  type Params = <LiteralAlgorithmSignMachine as SignMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::Params;
  type Keys = <LiteralAlgorithmSignMachine as SignMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::Keys;
  type Preprocess = <LiteralAlgorithmSignMachine as SignMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::Preprocess;
  type SignatureShare = <LiteralAlgorithmSignMachine as SignMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::SignatureShare;
  type SignatureMachine = ActionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!()
  }
  fn from_cache(
    _params: Self::Params,
    _keys: Self::Keys,
    _cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!()
  }

  fn read_preprocess<R: io::Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.machine.read_preprocess(reader)
  }
  fn sign(
    self,
    commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Self::SignatureShare), FrostError> {
    assert!(msg.is_empty());
    self.machine.sign(commitments, &self.action.message()).map(|(machine, shares)| {
      (ActionSignatureMachine { key: self.key, action: self.action, machine }, shares)
    })
  }
}

impl SignatureMachine<Transaction> for ActionSignatureMachine {
  type SignatureShare = <LiteralAlgorithmSignatureMachine as SignatureMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::SignatureShare;

  fn read_share<R: io::Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.machine.read_share(reader)
  }

  fn complete(
    self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    self.machine.complete(shares).map(|signature| {
      let s = signature.s;
      let c = Signature::challenge(signature.R, &self.key, &self.action.message());
      Transaction(self.action, Signature::new(c, s))
    })
  }
}
