use std::{io, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use ciphersuite::{Ciphersuite, Secp256k1};
use frost::{
  dkg::{Participant, ThresholdKeys},
  FrostError,
  algorithm::*,
  sign::*,
};

use alloy_core::primitives::U256;

use serai_client::networks::ethereum::Address;

use scheduler::SignableTransaction;

use ethereum_primitives::keccak256;
use ethereum_schnorr::{PublicKey, Signature};
use ethereum_router::{Coin, OutInstructions, Executed, Router};

use crate::output::OutputId;

#[derive(Clone, PartialEq, Debug)]
pub(crate) enum Action {
  SetKey { chain_id: U256, nonce: u64, key: PublicKey },
  Batch { chain_id: U256, nonce: u64, outs: Vec<(Address, (Coin, U256))> },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Eventuality(pub(crate) Executed);

impl Action {
  fn nonce(&self) -> u64 {
    match self {
      Action::SetKey { nonce, .. } | Action::Batch { nonce, .. } => *nonce,
    }
  }

  fn message(&self) -> Vec<u8> {
    match self {
      Action::SetKey { chain_id, nonce, key } => Router::update_serai_key_message(*chain_id, *nonce, key),
      Action::Batch { chain_id, nonce, outs } => Router::execute_message(*chain_id, *nonce, OutInstructions::from(outs.as_ref())),
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
pub(crate) struct Transaction(Action, Signature);
impl scheduler::Transaction for Transaction {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    /*
    let buf: Vec<u8> = borsh::from_reader(reader)?;
    // We can only read this from a &[u8], hence prior reading into a Vec<u8>
    <TxLegacy as alloy_rlp::Decodable>::decode(&mut buf.as_slice())
      .map(Self)
      .map_err(io::Error::other)
    */
    let action = Action::read(reader)?;
    let signature = Signature::read(reader)?;
    Ok(Transaction(action, signature))
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    /*
    let mut buf = Vec::with_capacity(256);
    <TxLegacy as alloy_rlp::Encodable>::encode(&self.0, &mut buf);
    borsh::BorshSerialize::serialize(&buf, writer)
    */
    self.0.write(writer)?;
    self.1.write(writer)?;
    Ok(())
  }
}

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

#[derive(Clone)]
pub(crate) struct ClonableTransctionMachine(ThresholdKeys<Secp256k1>, Action);

type LiteralAlgorithmMachine = AlgorithmMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;
type LiteralAlgorithmSignMachine =
  AlgorithmSignMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;

pub(crate) struct ActionSignMachine(PublicKey, Action, LiteralAlgorithmSignMachine);

type LiteralAlgorithmSignatureMachine =
  AlgorithmSignatureMachine<Secp256k1, IetfSchnorr<Secp256k1, EthereumHram>>;

pub(crate) struct ActionSignatureMachine(PublicKey, Action, LiteralAlgorithmSignatureMachine);

impl PreprocessMachine for ClonableTransctionMachine {
  type Preprocess = <LiteralAlgorithmMachine as PreprocessMachine>::Preprocess;
  type Signature = Transaction;
  type SignMachine = ActionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    let (machine, preprocess) = AlgorithmMachine::new(IetfSchnorr::<Secp256k1, EthereumHram>::ietf(), self.0.clone())
      .preprocess(rng);
    (ActionSignMachine(PublicKey::new(self.0.group_key()).expect("signing with non-representable key"), self.1, machine), preprocess)
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
    params: Self::Params,
    keys: Self::Keys,
    cache: CachedPreprocess,
) -> (Self, Self::Preprocess) {
    unimplemented!()
  }

  fn read_preprocess<R: io::Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.2.read_preprocess(reader)
  }
  fn sign(
    self,
    commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Self::SignatureShare), FrostError> {
    assert!(msg.is_empty());
    self
      .2
      .sign(commitments, &self.1.message())
      .map(|(machine, shares)| (ActionSignatureMachine(self.0, self.1, machine), shares))
  }
}

impl SignatureMachine<Transaction> for ActionSignatureMachine {
  type SignatureShare = <LiteralAlgorithmSignatureMachine as SignatureMachine<
    <LiteralAlgorithmMachine as PreprocessMachine>::Signature,
  >>::SignatureShare;

  fn read_share<R: io::Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.2.read_share(reader)
  }

  fn complete(
    self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    /*
    match self.1 {
      Action::SetKey { chain_id: _, nonce: _, key } => self.0.update_serai_key(key, signature),
      Action::Batch { chain_id: _, nonce: _, outs } => self.0.execute(outs, signature),
    }
    */
    self.2.complete(shares).map(|signature| {
      let s = signature.s;
      let c = Signature::challenge(signature.R, &self.0, &self.1.message());
      Transaction(self.1, Signature::new(c, s))
    })
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
    ClonableTransctionMachine(keys, self)
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
