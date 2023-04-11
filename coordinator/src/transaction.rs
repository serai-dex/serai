use std::{io, collections::HashMap};

use blake2::{Digest, Blake2s256};

use frost::Participant;

#[rustfmt::skip]
use tributary::{
  ReadWrite, Signed, TransactionError, TransactionKind, Transaction as TransactionTrait
};

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

  SignPreprocess(SignData),
  SignShare(SignData),

  FinalizedBlock(u64),

  BatchPreprocess(SignData),
  BatchShare(SignData),
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

          let mut share_len = [0; 1];
          reader.read_exact(&mut share_len)?;
          let share_len = usize::from(share_len[0]);

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

      2 => SignData::read(reader).map(Transaction::SignPreprocess),
      3 => SignData::read(reader).map(Transaction::SignShare),

      4 => {
        let mut block = [0; 8];
        reader.read_exact(&mut block)?;
        Ok(Transaction::FinalizedBlock(u64::from_le_bytes(block)))
      }

      5 => SignData::read(reader).map(Transaction::BatchPreprocess),
      6 => SignData::read(reader).map(Transaction::BatchShare),
      _ => Err(io::Error::new(io::ErrorKind::Other, "invalid transaction type")),
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Transaction::DkgCommitments(attempt, commitments, signed) => {
        writer.write_all(&[0])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(&u16::try_from(commitments.len()).unwrap().to_le_bytes())?;
        writer.write_all(commitments)?;
        signed.write(writer)
      }

      Transaction::DkgShares(attempt, shares, signed) => {
        writer.write_all(&[1])?;
        writer.write_all(&attempt.to_le_bytes())?;
        writer.write_all(&u16::try_from(shares.len()).unwrap().to_le_bytes())?;
        let mut share_len = None;
        for participant in 0 .. shares.len() {
          let share = &shares[&Participant::new(u16::try_from(participant + 1).unwrap()).unwrap()];
          if let Some(share_len) = share_len {
            if share.len() != share_len {
              panic!("variable length shares");
            }
          } else {
            writer.write_all(&[u8::try_from(share.len()).unwrap()])?;
            share_len = Some(share.len());
          }

          writer.write_all(share)?;
        }
        signed.write(writer)
      }

      Transaction::SignPreprocess(data) => {
        writer.write_all(&[2])?;
        data.write(writer)
      }
      Transaction::SignShare(data) => {
        writer.write_all(&[3])?;
        data.write(writer)
      }

      Transaction::FinalizedBlock(block) => {
        writer.write_all(&[4])?;
        writer.write_all(&block.to_le_bytes())
      }

      Transaction::BatchPreprocess(data) => {
        writer.write_all(&[5])?;
        data.write(writer)
      }
      Transaction::BatchShare(data) => {
        writer.write_all(&[6])?;
        data.write(writer)
      }
    }
  }
}

impl TransactionTrait for Transaction {
  fn kind(&self) -> TransactionKind {
    match self {
      Transaction::DkgCommitments(_, _, signed) => TransactionKind::Signed(signed.clone()),
      Transaction::DkgShares(_, _, signed) => TransactionKind::Signed(signed.clone()),

      Transaction::SignPreprocess(data) => TransactionKind::Signed(data.signed.clone()),
      Transaction::SignShare(data) => TransactionKind::Signed(data.signed.clone()),

      Transaction::FinalizedBlock(_) => TransactionKind::Provided,

      Transaction::BatchPreprocess(data) => TransactionKind::Signed(data.signed.clone()),
      Transaction::BatchShare(data) => TransactionKind::Signed(data.signed.clone()),
    }
  }

  fn hash(&self) -> [u8; 32] {
    let mut tx = self.serialize();
    if let TransactionKind::Signed(signed) = self.kind() {
      assert_eq!(&tx[(tx.len() - 64) ..], &signed.signature.serialize());
      tx.truncate(tx.len() - 64);
    }
    Blake2s256::digest(tx).into()
  }

  fn verify(&self) -> Result<(), TransactionError> {
    // TODO: Augment with checks that the Vecs can be deser'd and are for recognized IDs
    Ok(())
  }
}
