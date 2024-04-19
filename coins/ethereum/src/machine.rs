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

use alloy_core::primitives::U256;

use crate::{
  crypto::{PublicKey, EthereumHram, Signature},
  router::{
    abi::{Call as AbiCall, OutInstruction as AbiOutInstruction},
    Router,
  },
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Call {
  pub to: [u8; 20],
  pub value: U256,
  pub data: Vec<u8>,
}
impl Call {
  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut to = [0; 20];
    reader.read_exact(&mut to)?;

    let value = {
      let mut value_bytes = [0; 32];
      reader.read_exact(&mut value_bytes)?;
      U256::from_le_slice(&value_bytes)
    };

    let mut data_len = {
      let mut data_len = [0; 4];
      reader.read_exact(&mut data_len)?;
      usize::try_from(u32::from_le_bytes(data_len)).expect("u32 couldn't fit within a usize")
    };

    // A valid DoS would be to claim a 4 GB data is present for only 4 bytes
    // We read this in 1 KB chunks to only read data actually present (with a max DoS of 1 KB)
    let mut data = vec![];
    while data_len > 0 {
      let chunk_len = data_len.min(1024);
      let mut chunk = vec![0; chunk_len];
      reader.read_exact(&mut chunk)?;
      data.extend(&chunk);
      data_len -= chunk_len;
    }

    Ok(Call { to, value, data })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.to)?;
    writer.write_all(&self.value.as_le_bytes())?;

    let data_len = u32::try_from(self.data.len())
      .map_err(|_| io::Error::other("call data length exceeded 2**32"))?;
    writer.write_all(&data_len.to_le_bytes())?;
    writer.write_all(&self.data)
  }
}
impl From<Call> for AbiCall {
  fn from(call: Call) -> AbiCall {
    AbiCall { to: call.to.into(), value: call.value, data: call.data.into() }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OutInstructionTarget {
  Direct([u8; 20]),
  Calls(Vec<Call>),
}
impl OutInstructionTarget {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => {
        let mut addr = [0; 20];
        reader.read_exact(&mut addr)?;
        Ok(OutInstructionTarget::Direct(addr))
      }
      1 => {
        let mut calls_len = [0; 4];
        reader.read_exact(&mut calls_len)?;
        let calls_len = u32::from_le_bytes(calls_len);

        let mut calls = vec![];
        for _ in 0 .. calls_len {
          calls.push(Call::read(reader)?);
        }
        Ok(OutInstructionTarget::Calls(calls))
      }
      _ => Err(io::Error::other("unrecognized OutInstructionTarget"))?,
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      OutInstructionTarget::Direct(addr) => {
        writer.write_all(&[0])?;
        writer.write_all(addr)?;
      }
      OutInstructionTarget::Calls(calls) => {
        writer.write_all(&[1])?;
        let call_len = u32::try_from(calls.len())
          .map_err(|_| io::Error::other("amount of calls exceeded 2**32"))?;
        writer.write_all(&call_len.to_le_bytes())?;
        for call in calls {
          call.write(writer)?;
        }
      }
    }
    Ok(())
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutInstruction {
  pub target: OutInstructionTarget,
  pub value: U256,
}
impl OutInstruction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let target = OutInstructionTarget::read(reader)?;

    let value = {
      let mut value_bytes = [0; 32];
      reader.read_exact(&mut value_bytes)?;
      U256::from_le_slice(&value_bytes)
    };

    Ok(OutInstruction { target, value })
  }
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.target.write(writer)?;
    writer.write_all(&self.value.as_le_bytes())
  }
}
impl From<OutInstruction> for AbiOutInstruction {
  fn from(instruction: OutInstruction) -> AbiOutInstruction {
    match instruction.target {
      OutInstructionTarget::Direct(addr) => {
        AbiOutInstruction { to: addr.into(), calls: vec![], value: instruction.value }
      }
      OutInstructionTarget::Calls(calls) => AbiOutInstruction {
        to: [0; 20].into(),
        calls: calls.into_iter().map(Into::into).collect(),
        value: instruction.value,
      },
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouterCommand {
  UpdateSeraiKey { chain_id: U256, nonce: U256, key: PublicKey },
  Execute { chain_id: U256, nonce: U256, outs: Vec<OutInstruction> },
}

impl RouterCommand {
  pub fn msg(&self) -> Vec<u8> {
    match self {
      RouterCommand::UpdateSeraiKey { chain_id, nonce, key } => {
        Router::update_serai_key_message(*chain_id, *nonce, key)
      }
      RouterCommand::Execute { chain_id, nonce, outs } => Router::execute_message(
        *chain_id,
        *nonce,
        outs.iter().map(|out| out.clone().into()).collect(),
      ),
    }
  }

  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => {
        let mut chain_id = [0; 32];
        reader.read_exact(&mut chain_id)?;

        let mut nonce = [0; 32];
        reader.read_exact(&mut nonce)?;

        let key = PublicKey::new(Secp256k1::read_G(reader)?)
          .ok_or(io::Error::other("key for RouterCommand doesn't have an eth representation"))?;
        Ok(RouterCommand::UpdateSeraiKey {
          chain_id: U256::from_le_slice(&chain_id),
          nonce: U256::from_le_slice(&nonce),
          key,
        })
      }
      1 => {
        let mut chain_id = [0; 32];
        reader.read_exact(&mut chain_id)?;
        let chain_id = U256::from_le_slice(&chain_id);

        let mut nonce = [0; 32];
        reader.read_exact(&mut nonce)?;
        let nonce = U256::from_le_slice(&nonce);

        let mut outs_len = [0; 4];
        reader.read_exact(&mut outs_len)?;
        let outs_len = u32::from_le_bytes(outs_len);

        let mut outs = vec![];
        for _ in 0 .. outs_len {
          outs.push(OutInstruction::read(reader)?);
        }

        Ok(RouterCommand::Execute { chain_id, nonce, outs })
      }
      _ => Err(io::Error::other("reading unknown type of RouterCommand"))?,
    }
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      RouterCommand::UpdateSeraiKey { chain_id, nonce, key } => {
        writer.write_all(&[0])?;
        writer.write_all(&chain_id.as_le_bytes())?;
        writer.write_all(&nonce.as_le_bytes())?;
        writer.write_all(&key.A.to_bytes())
      }
      RouterCommand::Execute { chain_id, nonce, outs } => {
        writer.write_all(&[1])?;
        writer.write_all(&chain_id.as_le_bytes())?;
        writer.write_all(&nonce.as_le_bytes())?;
        writer.write_all(&u32::try_from(outs.len()).unwrap().to_le_bytes())?;
        for out in outs {
          out.write(writer)?;
        }
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

  pub fn command(&self) -> &RouterCommand {
    &self.command
  }

  pub fn signature(&self) -> &Signature {
    &self.signature
  }

  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let command = RouterCommand::read(reader)?;

    let mut sig = [0; 64];
    reader.read_exact(&mut sig)?;
    let signature = Signature::from_bytes(sig)?;

    Ok(SignedRouterCommand { command, signature })
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.command.write(writer)?;
    writer.write_all(&self.signature.to_bytes())
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
