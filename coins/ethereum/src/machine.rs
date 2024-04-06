use std::{
  io::{self, Read},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use transcript::RecommendedTranscript;

use frost::{curve::Secp256k1, Participant, ThresholdKeys, FrostError, algorithm::Schnorr, sign::*};

use ethers_core::types::U256;

use crate::{
  crypto::{PublicKey, EthereumHram, Signature},
  router::{abi::OutInstruction, Router},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouterCommand {
  UpdateSeraiKey { chain_id: U256, session: U256, key: PublicKey },
  Execute { chain_id: U256, nonce: U256, outs: Vec<OutInstruction> },
}

impl RouterCommand {
  fn msg(&self) -> Vec<u8> {
    match self {
      RouterCommand::UpdateSeraiKey { chain_id, session, key } => {
        Router::update_serai_key_message(*chain_id, *session, key)
      }
      RouterCommand::Execute { chain_id, nonce, outs } => {
        Router::execute_message(*chain_id, *nonce, outs.clone())
      }
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedRouterCommand {
  command: RouterCommand,
  signature: Signature,
}

pub struct RouterCommandMachine {
  key: PublicKey,
  command: RouterCommand,
  machine: AlgorithmMachine<Secp256k1, Schnorr<Secp256k1, RecommendedTranscript, EthereumHram>>,
}

impl PreprocessMachine for RouterCommandMachine {
  type Preprocess = Preprocess<Secp256k1, ()>;
  type Signature = SignedRouterCommand;
  type SignMachine = RouterCommandSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    let (machine, preprocess) = self.machine.preprocess(rng);

    (RouterCommandSignMachine { key: self.key, command: self.command, machine }, preprocess)
  }
}

pub struct RouterCommandSignMachine {
  key: PublicKey,
  command: RouterCommand,
  machine: AlgorithmSignMachine<Secp256k1, Schnorr<Secp256k1, RecommendedTranscript, EthereumHram>>,
}

impl SignMachine<SignedRouterCommand> for RouterCommandSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Secp256k1>;
  type Preprocess = Preprocess<Secp256k1, ()>;
  type SignatureShare = SignatureShare<Secp256k1>;
  type SignatureMachine = RouterCommandSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "RouterCommand machines don't support caching their preprocesses due to {}",
      "being already bound to a specific command"
    );
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Secp256k1>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!(
      "RouterCommand machines don't support caching their preprocesses due to {}",
      "being already bound to a specific command"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.machine.read_preprocess(reader)
  }

  fn sign(
    self,
    commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(RouterCommandSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      panic!("message was passed to a RouterCommand machine when it generates its own");
    }

    let (machine, share) = self.machine.sign(commitments, &self.command.msg())?;

    Ok((RouterCommandSignatureMachine { key: self.key, command: self.command, machine }, share))
  }
}

pub struct RouterCommandSignatureMachine {
  key: PublicKey,
  command: RouterCommand,
  machine:
    AlgorithmSignatureMachine<Secp256k1, Schnorr<Secp256k1, RecommendedTranscript, EthereumHram>>,
}

impl SignatureMachine<SignedRouterCommand> for RouterCommandSignatureMachine {
  type SignatureShare = SignatureShare<Secp256k1>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.machine.read_share(reader)
  }

  fn complete(
    self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<SignedRouterCommand, FrostError> {
    let sig = self.machine.complete(shares)?;
    let signature = Signature::new(&self.key, &self.command.msg(), sig)
      .expect("machine produced an invalid signature");
    Ok(SignedRouterCommand { command: self.command, signature })
  }
}
