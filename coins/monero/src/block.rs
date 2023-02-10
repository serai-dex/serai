use std::io::{self, Read, Write};

use crate::{
  serialize::*,
  transaction::{Input, Transaction},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
  pub major_version: u64,
  pub minor_version: u64,
  pub timestamp: u64,
  pub previous: [u8; 32],
  pub nonce: u32,
}

impl BlockHeader {
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.major_version, w)?;
    write_varint(&self.minor_version, w)?;
    write_varint(&self.timestamp, w)?;
    w.write_all(&self.previous)?;
    w.write_all(&self.nonce.to_le_bytes())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<BlockHeader> {
    Ok(BlockHeader {
      major_version: read_varint(r)?,
      minor_version: read_varint(r)?,
      timestamp: read_varint(r)?,
      previous: read_bytes(r)?,
      nonce: read_bytes(r).map(u32::from_le_bytes)?,
    })
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
  pub header: BlockHeader,
  pub miner_tx: Transaction,
  pub txs: Vec<[u8; 32]>,
}

impl Block {
  pub fn number(&self) -> usize {
    match self.miner_tx.prefix.inputs.get(0) {
      Some(Input::Gen(number)) => (*number).try_into().unwrap(),
      _ => panic!("invalid block, miner TX didn't have a Input::Gen"),
    }
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.header.write(w)?;
    self.miner_tx.write(w)?;
    write_varint(&self.txs.len().try_into().unwrap(), w)?;
    for tx in &self.txs {
      w.write_all(tx)?;
    }
    Ok(())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Block> {
    Ok(Block {
      header: BlockHeader::read(r)?,
      miner_tx: Transaction::read(r)?,
      txs: (0 .. read_varint(r)?).map(|_| read_bytes(r)).collect::<Result<_, _>>()?,
    })
  }
}
