use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use crate::{
  hash,
  serialize::*,
  transaction::{Input, Transaction},
};

mod merkle_root;

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

  pub fn tx_merkle_root(&self) -> [u8; 32] {
    merkle_root::tree_hash(self.miner_tx.hash(), &self.txs)
  }

  pub fn serialize_hashable(&self) -> Vec<u8> {
    let mut blob = self.header.serialize();
    blob.extend_from_slice(&self.tx_merkle_root());
    write_varint(&(1 + u64::try_from(self.txs.len()).unwrap()), &mut blob).unwrap();

    let mut out = Vec::with_capacity(8 + blob.len());
    write_varint(&u64::try_from(blob.len()).unwrap(), &mut out).unwrap();
    out.append(&mut blob);

    out
  }

  pub fn id(&self) -> [u8; 32] {
    // TODO: Handle block 202612
    // https://monero.stackexchange.com/questions/421/what-happened-at-block-202612
    // If this block's header is fully-equivalent to 202612, return the malformed hash instead
    hash(&self.serialize_hashable())
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
