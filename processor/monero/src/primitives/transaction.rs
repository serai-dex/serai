use std::io;

use rand_core::{RngCore, CryptoRng};

use ciphersuite::Ed25519;
use frost::{dkg::ThresholdKeys, sign::PreprocessMachine};

use monero_wallet::{
  transaction::Transaction as MTransaction,
  send::{
    SignableTransaction as MSignableTransaction, TransactionMachine, Eventuality as MEventuality,
  },
};

use crate::output::OutputId;

#[derive(Clone, Debug)]
pub(crate) struct Transaction(pub(crate) MTransaction);

impl From<MTransaction> for Transaction {
  fn from(tx: MTransaction) -> Self {
    Self(tx)
  }
}

impl scheduler::Transaction for Transaction {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    MTransaction::read(reader).map(Self)
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.0.write(writer)
  }
}

#[derive(Clone, Debug)]
pub(crate) struct SignableTransaction {
  id: [u8; 32],
  signable: MSignableTransaction,
}

#[derive(Clone)]
pub(crate) struct ClonableTransctionMachine(MSignableTransaction, ThresholdKeys<Ed25519>);
impl PreprocessMachine for ClonableTransctionMachine {
  type Preprocess = <TransactionMachine as PreprocessMachine>::Preprocess;
  type Signature = <TransactionMachine as PreprocessMachine>::Signature;
  type SignMachine = <TransactionMachine as PreprocessMachine>::SignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    self.0.multisig(self.1).expect("incorrect keys used for SignableTransaction").preprocess(rng)
  }
}

impl scheduler::SignableTransaction for SignableTransaction {
  type Transaction = Transaction;
  type Ciphersuite = Ed25519;
  type PreprocessMachine = ClonableTransctionMachine;

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut id = [0; 32];
    reader.read_exact(&mut id)?;

    let signable = MSignableTransaction::read(reader)?;
    Ok(SignableTransaction { id, signable })
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.id)?;
    self.signable.write(writer)
  }

  fn id(&self) -> [u8; 32] {
    self.id
  }

  fn sign(self, keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    ClonableTransctionMachine(self.signable, keys)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Eventuality {
  id: [u8; 32],
  singular_spent_output: Option<OutputId>,
  eventuality: MEventuality,
}

impl primitives::Eventuality for Eventuality {
  type OutputId = OutputId;

  fn id(&self) -> [u8; 32] {
    self.id
  }

  // We define the lookup as our ID since the resolving transaction only has a singular possible ID
  fn lookup(&self) -> Vec<u8> {
    self.eventuality.extra()
  }

  fn singular_spent_output(&self) -> Option<Self::OutputId> {
    self.singular_spent_output
  }

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut id = [0; 32];
    reader.read_exact(&mut id)?;

    let singular_spent_output = {
      let mut singular_spent_output_opt = [0xff];
      reader.read_exact(&mut singular_spent_output_opt)?;
      assert!(singular_spent_output_opt[0] <= 1);
      (singular_spent_output_opt[0] == 1)
        .then(|| -> io::Result<_> {
          let mut singular_spent_output = [0; 32];
          reader.read_exact(&mut singular_spent_output)?;
          Ok(OutputId(singular_spent_output))
        })
        .transpose()?
    };

    let eventuality = MEventuality::read(reader)?;
    Ok(Self { id, singular_spent_output, eventuality })
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.id)?;

    if let Some(singular_spent_output) = self.singular_spent_output {
      writer.write_all(&[1])?;
      writer.write_all(singular_spent_output.as_ref())?;
    } else {
      writer.write_all(&[0])?;
    }

    self.eventuality.write(writer)
  }
}
