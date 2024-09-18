use std::io;

use ciphersuite::Secp256k1;
use frost::dkg::ThresholdKeys;

use alloy_core::primitives::U256;

use serai_client::networks::ethereum::Address;

use scheduler::SignableTransaction;

use ethereum_primitives::keccak256;
use ethereum_schnorr::{PublicKey, Signature};
use ethereum_router::{Coin, OutInstructions, Executed, Router};

use crate::{output::OutputId, machine::ClonableTransctionMachine};

#[derive(Clone, PartialEq, Debug)]
pub(crate) enum Action {
  SetKey { chain_id: U256, nonce: u64, key: PublicKey },
  Batch { chain_id: U256, nonce: u64, outs: Vec<(Address, (Coin, U256))> },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Eventuality(pub(crate) Executed);

impl Action {
  pub(crate) fn nonce(&self) -> u64 {
    match self {
      Action::SetKey { nonce, .. } | Action::Batch { nonce, .. } => *nonce,
    }
  }

  pub(crate) fn message(&self) -> Vec<u8> {
    match self {
      Action::SetKey { chain_id, nonce, key } => {
        Router::update_serai_key_message(*chain_id, *nonce, key)
      }
      Action::Batch { chain_id, nonce, outs } => {
        Router::execute_message(*chain_id, *nonce, OutInstructions::from(outs.as_ref()))
      }
    }
  }

  pub(crate) fn eventuality(&self) -> Eventuality {
    Eventuality(match self {
      Self::SetKey { chain_id: _, nonce, key } => {
        Executed::SetKey { nonce: *nonce, key: key.eth_repr() }
      }
      Self::Batch { chain_id, nonce, outs } => Executed::Batch {
        nonce: *nonce,
        message_hash: keccak256(Router::execute_message(
          *chain_id,
          *nonce,
          OutInstructions::from(outs.as_ref()),
        )),
      },
    })
  }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Transaction(pub(crate) Action, pub(crate) Signature);
impl scheduler::Transaction for Transaction {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let action = Action::read(reader)?;
    let signature = Signature::read(reader)?;
    Ok(Transaction(action, signature))
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.0.write(writer)?;
    self.1.write(writer)?;
    Ok(())
  }
}

impl SignableTransaction for Action {
  type Transaction = Transaction;
  type Ciphersuite = Secp256k1;
  type PreprocessMachine = ClonableTransctionMachine;

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    if kind[0] >= 2 {
      Err(io::Error::other("unrecognized Action type"))?;
    }

    let mut chain_id = [0; 32];
    reader.read_exact(&mut chain_id)?;
    let chain_id = U256::from_le_bytes(chain_id);

    let mut nonce = [0; 8];
    reader.read_exact(&mut nonce)?;
    let nonce = u64::from_le_bytes(nonce);

    Ok(match kind[0] {
      0 => {
        let mut key = [0; 32];
        reader.read_exact(&mut key)?;
        let key =
          PublicKey::from_eth_repr(key).ok_or_else(|| io::Error::other("invalid key in Action"))?;

        Action::SetKey { chain_id, nonce, key }
      }
      1 => {
        let mut outs_len = [0; 4];
        reader.read_exact(&mut outs_len)?;
        let outs_len = usize::try_from(u32::from_le_bytes(outs_len)).unwrap();

        let mut outs = vec![];
        for _ in 0 .. outs_len {
          let address = borsh::from_reader(reader)?;
          let coin = Coin::read(reader)?;

          let mut amount = [0; 32];
          reader.read_exact(&mut amount)?;
          let amount = U256::from_le_bytes(amount);

          outs.push((address, (coin, amount)));
        }
        Action::Batch { chain_id, nonce, outs }
      }
      _ => unreachable!(),
    })
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    match self {
      Self::SetKey { chain_id, nonce, key } => {
        writer.write_all(&[0])?;
        writer.write_all(&chain_id.as_le_bytes())?;
        writer.write_all(&nonce.to_le_bytes())?;
        writer.write_all(&key.eth_repr())
      }
      Self::Batch { chain_id, nonce, outs } => {
        writer.write_all(&[1])?;
        writer.write_all(&chain_id.as_le_bytes())?;
        writer.write_all(&nonce.to_le_bytes())?;
        writer.write_all(&u32::try_from(outs.len()).unwrap().to_le_bytes())?;
        for (address, (coin, amount)) in outs {
          borsh::BorshSerialize::serialize(address, writer)?;
          coin.write(writer)?;
          writer.write_all(&amount.as_le_bytes())?;
        }
        Ok(())
      }
    }
  }

  fn id(&self) -> [u8; 32] {
    let mut res = [0; 32];
    res[.. 8].copy_from_slice(&self.nonce().to_le_bytes());
    res
  }

  fn sign(self, keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    ClonableTransctionMachine { keys, action: self }
  }
}

impl primitives::Eventuality for Eventuality {
  type OutputId = OutputId;

  fn id(&self) -> [u8; 32] {
    let mut res = [0; 32];
    res[.. 8].copy_from_slice(&self.0.nonce().to_le_bytes());
    res
  }

  fn lookup(&self) -> Vec<u8> {
    self.0.nonce().to_le_bytes().to_vec()
  }

  fn singular_spent_output(&self) -> Option<Self::OutputId> {
    None
  }

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    Executed::read(reader).map(Self)
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.0.write(writer)
  }
}
