use std::io;

use rand_core::{RngCore, CryptoRng};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};
use frost::{dkg::ThresholdKeys, sign::PreprocessMachine};

use ethereum_serai::{crypto::PublicKey, machine::*};

use crate::output::OutputId;

#[derive(Clone, Debug)]
pub(crate) struct Transaction(pub(crate) SignedRouterCommand);

impl From<SignedRouterCommand> for Transaction {
  fn from(signed_router_command: SignedRouterCommand) -> Self {
    Self(signed_router_command)
  }
}

impl scheduler::Transaction for Transaction {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    SignedRouterCommand::read(reader).map(Self)
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.0.write(writer)
  }
}

#[derive(Clone, Debug)]
pub(crate) struct SignableTransaction(pub(crate) RouterCommand);

#[derive(Clone)]
pub(crate) struct ClonableTransctionMachine(RouterCommand, ThresholdKeys<Secp256k1>);
impl PreprocessMachine for ClonableTransctionMachine {
  type Preprocess = <RouterCommandMachine as PreprocessMachine>::Preprocess;
  type Signature = <RouterCommandMachine as PreprocessMachine>::Signature;
  type SignMachine = <RouterCommandMachine as PreprocessMachine>::SignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    // TODO: Use a proper error here, not an Option
    RouterCommandMachine::new(self.1.clone(), self.0.clone()).unwrap().preprocess(rng)
  }
}

impl scheduler::SignableTransaction for SignableTransaction {
  type Transaction = Transaction;
  type Ciphersuite = Secp256k1;
  type PreprocessMachine = ClonableTransctionMachine;

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    RouterCommand::read(reader).map(Self)
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.0.write(writer)
  }

  fn id(&self) -> [u8; 32] {
    let mut res = [0; 32];
    // TODO: Add getter for the nonce
    match self.0 {
      RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
        res[.. 8].copy_from_slice(&nonce.as_le_bytes());
      }
    }
    res
  }

  fn sign(self, keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    ClonableTransctionMachine(self.0, keys)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Eventuality(pub(crate) PublicKey, pub(crate) RouterCommand);

impl primitives::Eventuality for Eventuality {
  type OutputId = OutputId;

  fn id(&self) -> [u8; 32] {
    let mut res = [0; 32];
    match self.1 {
      RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
        res[.. 8].copy_from_slice(&nonce.as_le_bytes());
      }
    }
    res
  }

  fn lookup(&self) -> Vec<u8> {
    match self.1 {
      RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
        nonce.as_le_bytes().to_vec()
      }
    }
  }

  fn singular_spent_output(&self) -> Option<Self::OutputId> {
    None
  }

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let point = Secp256k1::read_G(reader)?;
    let command = RouterCommand::read(reader)?;
    Ok(Eventuality(
      PublicKey::new(point).ok_or(io::Error::other("unusable key within Eventuality"))?,
      command,
    ))
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(self.0.point().to_bytes().as_slice())?;
    self.1.write(writer)
  }
}
