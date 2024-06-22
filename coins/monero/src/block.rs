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

/// A Monero block's header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
  /// The major version of the protocol, denoting the hard fork.
  pub major_version: u8,
  /// The minor version of the protocol.
  pub minor_version: u8,
  /// Seconds since the epoch.
  pub timestamp: u64,
  /// The previous block's hash.
  pub previous: [u8; 32],
  /// The nonce used to mine the block.
  ///
  /// Miners should increment this while attempting to find a block with a hash satisfying the PoW
  /// rules.
  pub nonce: u32,
}

impl BlockHeader {
  /// Write the BlockHeader.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.major_version, w)?;
    write_varint(&self.minor_version, w)?;
    write_varint(&self.timestamp, w)?;
    w.write_all(&self.previous)?;
    w.write_all(&self.nonce.to_le_bytes())
  }

  /// Serialize the BlockHeader to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Read a BlockHeader.
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

/// A Monero block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
  /// The block's header.
  pub header: BlockHeader,
  /// The miner's transaction.
  pub miner_tx: Transaction,
  /// The transactions within this block.
  pub txs: Vec<[u8; 32]>,
}

impl Block {
  /// The zero-index position of this block within the blockchain.
  ///
  /// This information comes from the Block's miner transaction. If the miner transaction isn't
  /// structed as expected, this will return None.
  pub fn number(&self) -> Option<u64> {
    match self.miner_tx.prefix.inputs.first() {
      Some(Input::Gen(number)) => Some(*number),
      _ => None,
    }
  }

  /// Write the BlockHeader.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.header.write(w)?;
    self.miner_tx.write(w)?;
    write_varint(&self.txs.len(), w)?;
    for tx in &self.txs {
      w.write_all(tx)?;
    }
    Ok(())
  }

  /// Serialize the BlockHeader to a Vec<u8>.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Serialize the block as required for the proof of work hash.
  ///
  /// This is distinct from the serialization required for the block hash. To get the block hash,
  /// use the [`Block::hash`] function.
  pub fn serialize_pow_hash(&self) -> Vec<u8> {
    let mut blob = self.header.serialize();
    blob.extend_from_slice(&merkle_root(self.miner_tx.hash(), &self.txs));
    write_varint(&(1 + u64::try_from(self.txs.len()).unwrap()), &mut blob).unwrap();
    blob
  }

  /// Get the hash of this block.
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

  /// Read a BlockHeader.
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
