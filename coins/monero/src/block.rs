use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use crate::{
  hash,
  merkle::merkle_root,
  serialize::*,
  transaction::{Input, Transaction},
};

const CORRECT_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("426d16cff04c71f8b16340b722dc4010a2dd3831c22041431f772547ba6e331a");
const EXISTING_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698");

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

  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    Ok(Self {
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

  fn tx_merkle_root(&self) -> [u8; 32] {
    merkle_root(self.miner_tx.hash(), &self.txs)
  }

  fn serialize_hashable(&self) -> Vec<u8> {
    let mut blob = self.header.serialize();
    blob.extend_from_slice(&self.tx_merkle_root());
    write_varint(&(1 + u64::try_from(self.txs.len()).unwrap()), &mut blob).unwrap();

    let mut out = Vec::with_capacity(8 + blob.len());
    write_varint(&u64::try_from(blob.len()).unwrap(), &mut out).unwrap();
    out.append(&mut blob);

    out
  }

  pub fn hash(&self) -> [u8; 32] {
    let hash = hash(&self.serialize_hashable());
    if hash == CORRECT_BLOCK_HASH_202612 {
      return EXISTING_BLOCK_HASH_202612;
    };

    hash
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    Ok(Self {
      header: BlockHeader::read(r)?,
      miner_tx: Transaction::read(r)?,
      txs: (0 .. read_varint(r)?).map(|_| read_bytes(r)).collect::<Result<_, _>>()?,
    })
  }
}
