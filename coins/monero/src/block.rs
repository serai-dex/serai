use crate::{
  serialize::*,
  transaction::Transaction
};

#[derive(Clone, Debug)]
pub struct BlockHeader {
  pub major_version: u64,
  pub minor_version: u64,
  pub timestamp: u64,
  pub previous: [u8; 32],
  pub nonce: u32
}

impl BlockHeader {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    write_varint(&self.major_version, w)?;
    write_varint(&self.minor_version, w)?;
    write_varint(&self.timestamp, w)?;
    w.write_all(&self.previous)?;
    w.write_all(&self.nonce.to_le_bytes())
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<BlockHeader> {
    Ok(
      BlockHeader {
        major_version: read_varint(r)?,
        minor_version: read_varint(r)?,
        timestamp: read_varint(r)?,
        previous: { let mut previous = [0; 32]; r.read_exact(&mut previous)?; previous },
        nonce: { let mut nonce = [0; 4]; r.read_exact(&mut nonce)?; u32::from_le_bytes(nonce) }
      }
    )
  }
}

#[derive(Clone, Debug)]
pub struct Block {
  pub header: BlockHeader,
  pub miner_tx: Transaction,
  pub txs: Vec<[u8; 32]>
}

impl Block {
  pub fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
    self.header.serialize(w)?;
    self.miner_tx.serialize(w)?;
    write_varint(&self.txs.len().try_into().unwrap(), w)?;
    for tx in &self.txs {
      w.write_all(tx)?;
    }
    Ok(())
  }

  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Block> {
    Ok(
      Block {
        header: BlockHeader::deserialize(r)?,
        miner_tx: Transaction::deserialize(r)?,
        txs: (0 .. read_varint(r)?).map(
          |_| { let mut tx = [0; 32]; r.read_exact(&mut tx).map(|_| tx) }
        ).collect::<Result<_, _>>()?
      }
    )
  }
}
