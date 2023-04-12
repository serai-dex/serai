use std::{
  io,
  collections::{HashSet, HashMap},
};

use thiserror::Error;

use blake2::{Digest, Blake2s256};

use ciphersuite::{Ciphersuite, Ristretto};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum BlockError {
  /// Header specified a parent which wasn't the chain tip.
  #[error("header doesn't build off the chain tip")]
  InvalidParent,
  /// Header specified an invalid transactions merkle tree hash.
  #[error("header transactions hash is incorrect")]
  InvalidTransactions,
  /// An included transaction was invalid.
  #[error("included transaction had an error")]
  TransactionError(TransactionError),
}

use crate::{
  ReadWrite, TransactionError, Signed, TransactionKind, Transaction, ProvidedTransactions, merkle,
  verify_transaction,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
  pub parent: [u8; 32],
  pub transactions: [u8; 32],
}

impl ReadWrite for BlockHeader {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut header = BlockHeader { parent: [0; 32], transactions: [0; 32] };
    reader.read_exact(&mut header.parent)?;
    reader.read_exact(&mut header.transactions)?;
    Ok(header)
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.parent)?;
    writer.write_all(&self.transactions)
  }
}

impl BlockHeader {
  fn hash(&self) -> [u8; 32] {
    Blake2s256::digest([b"tributary_block".as_ref(), &self.serialize()].concat()).into()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block<T: Transaction> {
  pub header: BlockHeader,
  pub transactions: Vec<T>,
}

impl<T: Transaction> ReadWrite for Block<T> {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let header = BlockHeader::read(reader)?;

    let mut txs = [0; 4];
    reader.read_exact(&mut txs)?;
    let txs = u32::from_le_bytes(txs);

    let mut transactions = Vec::with_capacity(usize::try_from(txs).unwrap());
    for _ in 0 .. txs {
      transactions.push(T::read(reader)?);
    }

    Ok(Block { header, transactions })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.header.write(writer)?;
    writer.write_all(&u32::try_from(self.transactions.len()).unwrap().to_le_bytes())?;
    for tx in &self.transactions {
      tx.write(writer)?;
    }
    Ok(())
  }
}

impl<T: Transaction> Block<T> {
  /// Create a new block.
  ///
  /// mempool is expected to only have valid, non-conflicting transactions.
  pub(crate) fn new(
    parent: [u8; 32],
    provided: &ProvidedTransactions<T>,
    mempool: HashMap<[u8; 32], T>,
  ) -> Self {
    let mut txs = vec![];
    for tx in provided.transactions.values().cloned() {
      txs.push(tx);
    }
    for tx in mempool.values().cloned() {
      assert!(tx.kind() != TransactionKind::Provided, "provided transaction entered mempool");
      txs.push(tx);
    }

    // Sort txs by nonces.
    let nonce = |tx: &T| {
      if let TransactionKind::Signed(Signed { nonce, .. }) = tx.kind() {
        *nonce
      } else {
        0
      }
    };
    txs.sort_by(|a, b| nonce(a).partial_cmp(&nonce(b)).unwrap());

    // Check the sort.
    let mut last = 0;
    for tx in &txs {
      let nonce = nonce(tx);
      if nonce < last {
        panic!("failed to sort txs by nonce");
      }
      last = nonce;
    }

    let hashes = txs.iter().map(Transaction::hash).collect::<Vec<_>>();
    Block { header: BlockHeader { parent, transactions: merkle(&hashes) }, transactions: txs }
  }

  pub fn hash(&self) -> [u8; 32] {
    self.header.hash()
  }

  pub fn verify(
    &self,
    genesis: [u8; 32],
    last_block: [u8; 32],
    mut locally_provided: HashSet<[u8; 32]>,
    mut next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
  ) -> Result<(), BlockError> {
    if self.header.parent != last_block {
      Err(BlockError::InvalidParent)?;
    }

    let mut txs = Vec::with_capacity(self.transactions.len());
    for tx in &self.transactions {
      match verify_transaction(tx, genesis, &mut locally_provided, &mut next_nonces) {
        Ok(()) => {}
        Err(e) => Err(BlockError::TransactionError(e))?,
      }

      txs.push(tx.hash());
    }

    if merkle(&txs) != self.header.transactions {
      Err(BlockError::InvalidTransactions)?;
    }

    Ok(())
  }
}
