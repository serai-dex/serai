use std::{
  io::{self, Read},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use transcript::{Transcript, RecommendedTranscript};

use group::GroupEncoding;
use frost::{
  curve::{Ciphersuite, Secp256k1},
  Participant, ThresholdKeys, FrostError,
  algorithm::Schnorr,
  sign::*,
};

use ethers_core::{types::U256, abi::AbiEncode};

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
  pub fn msg(&self) -> Vec<u8> {
    match self {
      RouterCommand::UpdateSeraiKey { chain_id, session, key } => {
        Router::update_serai_key_message(*chain_id, *session, key)
      }
      RouterCommand::Execute { chain_id, nonce, outs } => {
        Router::execute_message(*chain_id, *nonce, outs.clone())
      }
    }
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      RouterCommand::UpdateSeraiKey { chain_id, session, key } => {
        writer.write_all(&[0])?;

        let mut chain_id_bytes = [0; 32];
        chain_id.to_little_endian(&mut chain_id_bytes);
        writer.write_all(&chain_id_bytes)?;

        let mut session_bytes = [0; 32];
        session.to_little_endian(&mut session_bytes);
        writer.write_all(&session_bytes)?;

        writer.write_all(&key.A.to_bytes())
      }
      RouterCommand::Execute { chain_id, nonce, outs } => {
        writer.write_all(&[1])?;

        let mut chain_id_bytes = [0; 32];
        chain_id.to_little_endian(&mut chain_id_bytes);
        writer.write_all(&chain_id_bytes)?;

        let mut nonce_bytes = [0; 32];
        nonce.to_little_endian(&mut nonce_bytes);
        writer.write_all(&nonce_bytes)?;

        let outs = outs.clone().encode();
        writer.write_all(&u32::try_from(outs.len()).unwrap().to_le_bytes())?;
        writer.write_all(&outs)?;

        Ok(())
      }
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).unwrap();
    res
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedRouterCommand {
  command: RouterCommand,
  signature: Signature,
}

impl SignedRouterCommand {
  pub fn new(key: &PublicKey, command: RouterCommand, signature: &[u8; 64]) -> Option<Self> {
    let c = Secp256k1::read_F(&mut &signature[.. 32]).ok()?;
    let s = Secp256k1::read_F(&mut &signature[32 ..]).ok()?;
    let signature = Signature { c, s };

    if !signature.verify(key, &command.msg()) {
      None?
    }
    Some(SignedRouterCommand { command, signature })
  }

  pub fn signature(&self) -> &Signature {
    &self.signature
  }
}

pub struct RouterCommandMachine {
  key: PublicKey,
  command: RouterCommand,
  machine: AlgorithmMachine<Secp256k1, Schnorr<Secp256k1, RecommendedTranscript, EthereumHram>>,
}

impl RouterCommandMachine {
  pub fn new(keys: ThresholdKeys<Secp256k1>, command: RouterCommand) -> Option<Self> {
    // The Schnorr algorithm should be fine without this, even when using the IETF variant
    // If this is better and more comprehensive, we should do it, even if not necessary
    let mut transcript = RecommendedTranscript::new(b"ethereum-serai RouterCommandMachine v0.1");
    let key = keys.group_key();
    transcript.append_message(b"key", key.to_bytes());
    transcript.append_message(b"command", command.serialize());

    Some(Self {
      key: PublicKey::new(key)?,
      command,
      machine: AlgorithmMachine::new(Schnorr::new(transcript), keys),
    })
  }
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
