use std::{io, collections::HashMap};

use thiserror::Error;

use blake2::{Digest, Blake2s256};

use ciphersuite::{Ciphersuite, Ristretto};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum BlockError {
  /// Block was too large.
  #[error("block exceeded size limit")]
  TooLargeBlock,
  /// Header specified a parent which wasn't the chain tip.
  #[error("header doesn't build off the chain tip")]
  InvalidParent,
  /// Header specified an invalid transactions merkle tree hash.
  #[error("header transactions hash is incorrect")]
  InvalidTransactions,
  /// A provided transaction was placed after a non-provided transaction.
  #[error("a provided transaction was included after a non-provided transaction")]
  ProvidedAfterNonProvided,
  /// The block had a provided transaction this validator has yet to be provided.
  #[error("block had a provided transaction not yet locally provided: {0:?}")]
  NonLocalProvided([u8; 32]),
  /// The provided transaction was distinct from the locally provided transaction.
  #[error("block had a distinct provided transaction")]
  DistinctProvided,
  /// An included transaction was invalid.
  #[error("included transaction had an error")]
  TransactionError(TransactionError),
}

use crate::{
  BLOCK_SIZE_LIMIT, ReadWrite, TransactionError, Signed, TransactionKind, Transaction, merkle,
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
  pub fn hash(&self) -> [u8; 32] {
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
  pub(crate) fn new(parent: [u8; 32], provided: Vec<T>, mempool: Vec<T>) -> Self {
    let mut txs = provided;
    for tx in mempool {
      assert!(tx.kind() != TransactionKind::Provided, "provided transaction entered mempool");
      txs.push(tx);
    }

    // Check TXs are sorted by nonce.
    let nonce = |tx: &T| {
      if let TransactionKind::Signed(Signed { nonce, .. }) = tx.kind() {
        *nonce
      } else {
        0
      }
    };
    let mut last = 0;
    for tx in &txs {
      let nonce = nonce(tx);
      if nonce < last {
        panic!("failed to sort txs by nonce");
      }
      last = nonce;
    }

    let mut res =
      Block { header: BlockHeader { parent, transactions: [0; 32] }, transactions: txs };
    while res.serialize().len() > BLOCK_SIZE_LIMIT {
      assert!(res.transactions.pop().is_some());
    }
    let hashes = res.transactions.iter().map(Transaction::hash).collect::<Vec<_>>();
    res.header.transactions = merkle(&hashes);
    res
  }

  pub fn parent(&self) -> [u8; 32] {
    self.header.parent
  }

  pub fn hash(&self) -> [u8; 32] {
    self.header.hash()
  }

  pub(crate) fn verify(
    &self,
    genesis: [u8; 32],
    last_block: [u8; 32],
    locally_provided: &[[u8; 32]],
    mut next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,
  ) -> Result<(), BlockError> {
    if self.serialize().len() > BLOCK_SIZE_LIMIT {
      Err(BlockError::TooLargeBlock)?;
    }

    if self.header.parent != last_block {
      Err(BlockError::InvalidParent)?;
    }

    let mut found_non_provided = false;
    let mut txs = Vec::with_capacity(self.transactions.len());
    for (i, tx) in self.transactions.iter().enumerate() {
      txs.push(tx.hash());

      if tx.kind() == TransactionKind::Provided {
        if found_non_provided {
          Err(BlockError::ProvidedAfterNonProvided)?;
        }

        let Some(local) = locally_provided.get(i) else {
          Err(BlockError::NonLocalProvided(txs.pop().unwrap()))?
        };
        if txs.last().unwrap() != local {
          Err(BlockError::DistinctProvided)?;
        }

        // We don't need to call verify_transaction since we did when we locally provided this
        // transaction. Since it's identical, it must be valid
        continue;
      }

      found_non_provided = true;
      match verify_transaction(tx, genesis, &mut next_nonces) {
        Ok(()) => {}
        Err(e) => Err(BlockError::TransactionError(e))?,
      }
    }

    if merkle(&txs) != self.header.transactions {
      Err(BlockError::InvalidTransactions)?;
    }

    Ok(())
  }
}
