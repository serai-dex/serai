use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use crate::{
  io::*,
  primitives::keccak256,
  merkle::merkle_root,
  transaction::{Input, Transaction},
};

const CORRECT_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("426d16cff04c71f8b16340b722dc4010a2dd3831c22041431f772547ba6e331a");
const EXISTING_BLOCK_HASH_202612: [u8; 32] =
  hex_literal::hex!("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698");

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
  pub major_version: u8,
  pub minor_version: u8,
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
  pub fn number(&self) -> Option<u64> {
    match self.miner_tx.prefix.inputs.first() {
      Some(Input::Gen(number)) => Some(*number),
      _ => None,
    }
  }

  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.header.write(w)?;
    self.miner_tx.write(w)?;
    write_varint(&self.txs.len(), w)?;
    for tx in &self.txs {
      w.write_all(tx)?;
    }
    Ok(())
  }

  fn tx_merkle_root(&self) -> [u8; 32] {
    merkle_root(self.miner_tx.hash(), &self.txs)
  }

  /// Serialize the block as required for the proof of work hash.
  ///
  /// This is distinct from the serialization required for the block hash. To get the block hash,
  /// use the [`Block::hash`] function.
  pub fn serialize_hashable(&self) -> Vec<u8> {
    let mut blob = self.header.serialize();
    blob.extend_from_slice(&self.tx_merkle_root());
    write_varint(&(1 + u64::try_from(self.txs.len()).unwrap()), &mut blob).unwrap();

    blob
  }

  pub fn hash(&self) -> [u8; 32] {
    let mut hashable = self.serialize_hashable();
    // Monero pre-appends a VarInt of the block hashing blobs length before getting the block hash
    // but doesn't do this when getting the proof of work hash :)
    let mut hashing_blob = Vec::with_capacity(8 + hashable.len());
    write_varint(&u64::try_from(hashable.len()).unwrap(), &mut hashing_blob).unwrap();
    hashing_blob.append(&mut hashable);

    let hash = keccak256(hashing_blob);
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

  pub fn read<R: Read>(r: &mut R) -> io::Result<Block> {
    let header = BlockHeader::read(r)?;

    let miner_tx = Transaction::read(r)?;
    if !matches!(miner_tx.prefix.inputs.as_slice(), &[Input::Gen(_)]) {
      Err(io::Error::other("Miner transaction has incorrect input type."))?;
    }

    Ok(Block {
      header,
      miner_tx,
      txs: (0_usize .. read_varint(r)?).map(|_| read_bytes(r)).collect::<Result<_, _>>()?,
    })
  }
}
