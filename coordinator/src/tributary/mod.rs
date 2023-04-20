use std::{io, collections::HashMap};

use blake2::{Digest, Blake2s256};
use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{Ciphersuite, Ristretto};
use frost::Participant;

use scale::Encode;

use serai_client::validator_sets::primitives::{ValidatorSet, ValidatorSetData};

#[rustfmt::skip]
use tributary::{
  ReadWrite, Signed, TransactionError, TransactionKind, Transaction as TransactionTrait,
};

mod db;
pub use db::*;

pub mod scanner;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TributarySpec {
  serai_block: [u8; 32],
  start_time: u64,
  set: ValidatorSet,
  validators: Vec<(<Ristretto as Ciphersuite>::G, u64)>,
}

impl TributarySpec {
  pub fn new(
    serai_block: [u8; 32],
    start_time: u64,
    set: ValidatorSet,
    set_data: ValidatorSetData,
  ) -> TributarySpec {
    let mut validators = vec![];
    for (participant, amount) in set_data.participants {
      // TODO: Ban invalid keys from being validators on the Serai side
      let participant = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref())
        .expect("invalid key registered as participant");
      // Give one weight on Tributary per bond instance
      validators.push((participant, amount.0 / set_data.bond.0));
    }

    Self { serai_block, start_time, set, validators }
  }

  pub fn set(&self) -> ValidatorSet {
    self.set
  }

  pub fn genesis(&self) -> [u8; 32] {
    // Calculate the genesis for this Tributary
    let mut genesis = RecommendedTranscript::new(b"Serai Tributary Genesis");
    // This locks it to a specific Serai chain
    genesis.append_message(b"serai_block", self.serai_block);
    genesis.append_message(b"session", self.set.session.0.to_le_bytes());
    genesis.append_message(b"network", self.set.network.encode());
    let genesis = genesis.challenge(b"genesis");
    let genesis_ref: &[u8] = genesis.as_ref();
    genesis_ref[.. 32].try_into().unwrap()
  }

  pub fn start_time(&self) -> u64 {
    self.start_time
  }

  pub fn n(&self) -> u16 {
    // TODO: Support multiple key shares
    // self.validators.iter().map(|(_, weight)| u16::try_from(weight).unwrap()).sum()
    self.validators().len().try_into().unwrap()
  }

  pub fn t(&self) -> u16 {
    (2 * (self.n() / 3)) + 1
  }

  pub fn i(&self, key: <Ristretto as Ciphersuite>::G) -> Option<Participant> {
    let mut i = 1;
    // TODO: Support multiple key shares
    for (validator, _weight) in &self.validators {
      if validator == &key {
        // return (i .. (i + weight)).to_vec();
        return Some(Participant::new(i).unwrap());
      }
      // i += weight;
      i += 1;
    }
    None
  }

  pub fn validators(&self) -> HashMap<<Ristretto as Ciphersuite>::G, u64> {
    let mut res = HashMap::new();
    for (key, amount) in self.validators.clone() {
      res.insert(key, amount);
    }
    res
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignData {
  pub plan: [u8; 32],
  pub attempt: u32,

  pub data: Vec<u8>,

  pub signed: Signed,
}

impl ReadWrite for SignData {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut plan = [0; 32];
    reader.read_exact(&mut plan)?;

    let mut attempt = [0; 4];
    reader.read_exact(&mut attempt)?;
    let attempt = u32::from_le_bytes(attempt);

    let data = {
      let mut data_len = [0; 2];
      reader.read_exact(&mut data_len)?;
      let mut data = vec![0; usize::from(u16::from_le_bytes(data_len))];
      reader.read_exact(&mut data)?;
      data
    };

    let signed = Signed::read(reader)?;

    Ok(SignData { plan, attempt, data, signed })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.plan)?;
    writer.write_all(&self.attempt.to_le_bytes())?;

    if self.data.len() > u16::MAX.into() {
      // Currently, the largest sign item would be a Monero transaction
      // It provides 4 commitments per input (128 bytes), a 64-byte proof for them, along with a
      // key image and proof (96 bytes)
      // Even with all of that, we could support 227 inputs in a single TX
      // Monero is limited to 120 inputs per TX
      Err(io::Error::new(io::ErrorKind::Other, "signing data exceeded 65535 bytes"))?;
    }
    writer.write_all(&u16::try_from(self.data.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.data)?;

    self.signed.write(writer)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
  // Once this completes successfully, no more instances should be created.
  DkgCommitments(u32, Vec<u8>, Signed),
  DkgShares(u32, HashMap<Participant, Vec<u8>>, Signed),

  // When an external block is finalized, we can allow the associated batch IDs
  ExternalBlock(u64),
  // When a Serai block is finalized, with the contained batches, we can allow the associated plan
  // IDs
  SeraiBlock(u64),

  BatchPreprocess(SignData),
  BatchShare(SignData),

  SignPreprocess(SignData),
  SignShare(SignData),
}

impl ReadWrite for Transaction {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;

    match kind[0] {
      0 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let commitments = {
          let mut commitments_len = [0; 2];
          reader.read_exact(&mut commitments_len)?;
          let mut commitments = vec![0; usize::from(u16::from_le_bytes(commitments_len))];
          reader.read_exact(&mut commitments)?;
          commitments
        };

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgCommitments(attempt, commitments, signed))
      }

      1 => {
        let mut attempt = [0; 4];
        reader.read_exact(&mut attempt)?;
        let attempt = u32::from_le_bytes(attempt);

        let shares = {
          let mut share_quantity = [0; 2];
          reader.read_exact(&mut share_quantity)?;

          let mut share_len = [0; 2];
          reader.read_exact(&mut share_len)?;
          let share_len = usize::from(u16::from_le_bytes(share_len));

          let mut shares = HashMap::new();
          for i in 0 .. u16::from_le_bytes(share_quantity) {
            let participant = Participant::new(i + 1).unwrap();
            let mut share = vec![0; share_len];
            reader.read_exact(&mut share)?;
            shares.insert(participant, share);
          }
          shares
        };

        let signed = Signed::read(reader)?;

        Ok(Transaction::DkgShares(attempt, shares, signed))
      }

      2 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::ExternalBlock(u64::from_le_bytes(block)))
      }

      3 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::SeraiBlock(u64::from_le_bytes(block)))
      }

      4 => SignData::read(reader).map(Transaction::BatchPreprocess),
      5 => SignData::read(reader).map(Transaction::BatchShare),

      6 => SignData::read(reader).map(Transaction::SignPreprocess),
      7 => SignData::read(reader).map(Transaction::SignShare),

      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::DkgCommitments(attempt, commitments, signed) => {
        writer.write_all(&[0])?;
        writer.write_all(&attempt.to_le_bytes())?;
        if commitments.len() > u16::MAX.into() {
          // t commitments and an encryption key mean a u16 is fine until a threshold > 2000 occurs
          Err(io::Error::new(io::ErrorKind::Other, "dkg commitments exceeded 65535 bytes"))?;
        }
        writer.write_all(&u16::try_from(commitments.len()).unwrap().to_le_bytes())?;
        writer.write_all(commitments)?;
        signed.write(writer)
      }

      Transaction::DkgShares(attempt, shares, signed) => {
        writer.write_all(&[1])?;
        writer.write_all(&attempt.to_le_bytes())?;
        // Shares are indexed by non-zero u16s (Participants), so this can't fail
        writer.write_all(&u16::try_from(shares.len()).unwrap().to_le_bytes())?;
        let mut share_len = None;
        for participant in 0 .. shares.len() {
          let share = &shares[&Participant::new(u16::try_from(participant + 1).unwrap()).unwrap()];
          if let Some(share_len) = share_len {
            if share.len() != share_len {
              panic!("variable length shares");
            }
          } else {
            // For BLS12-381 G2, this would be:
            // - A 32-byte share
            // - A 96-byte ephemeral key
            // - A 128-byte signature
            // Hence why this has to be u16
            writer.write_all(&u16::try_from(share.len()).unwrap().to_le_bytes())?;
            share_len = Some(share.len());
          }

          writer.write_all(share)?;
        }
        signed.write(writer)
      }

      Transaction::ExternalBlock(block) => {
        writer.write_all(&[2])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::SeraiBlock(block) => {
        writer.write_all(&[3])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::BatchPreprocess(data) => {
        writer.write_all(&[4])?;
        data.write(writer)
      }
      Transaction::BatchShare(data) => {
        writer.write_all(&[5])?;
        data.write(writer)
      }

      Transaction::SignPreprocess(data) => {
        writer.write_all(&[6])?;
        data.write(writer)
      }
      Transaction::SignShare(data) => {
        writer.write_all(&[7])?;
        data.write(writer)
      }
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind<'_> {
    match self {
      Transaction::DkgCommitments(_, _, signed) => TransactionKind::Signed(signed),
      Transaction::DkgShares(_, _, signed) => TransactionKind::Signed(signed),

      Transaction::ExternalBlock(_) => TransactionKind::Provided("external"),
      Transaction::SeraiBlock(_) => TransactionKind::Provided("serai"),

      Transaction::BatchPreprocess(data) => TransactionKind::Signed(&data.signed),
      Transaction::BatchShare(data) => TransactionKind::Signed(&data.signed),

      Transaction::SignPreprocess(data) => TransactionKind::Signed(&data.signed),
      Transaction::SignShare(data) => TransactionKind::Signed(&data.signed),
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = self.serialize();
    if let TransactionKind::Signed(signed) = self.kind() {
      // Make sure the part we're cutting off is the signature
      assert_eq!(tx.drain((tx.len() - 64) ..).collect::<Vec<_>>(), signed.signature.serialize());
    }
    Blake2s256::digest(tx).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    // TODO: Augment with checks that the Vecs can be deser'd and are for recognized IDs

    if let Transaction::BatchShare(data) = self {
      if data.data.len() != 32 {
        Err(TransactionError::InvalidContent)?;
      }
    }

    Ok(())
  }
}
