use std::collections::HashMap;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db};

use crate::{
  ReadWrite, Signed, TransactionKind, Transaction, ProvidedError, ProvidedTransactions, BlockError,
  Block, Mempool,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Blockchain<D: Db, T: Transaction> {
  db: Option<D>,
  genesis: [u8; 32],

  block_number: u32,
  tip: [u8; 32],
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,

  provided: ProvidedTransactions<D, T>,
  mempool: Mempool<D, T>,
}

impl<D: Db, T: Transaction> Blockchain<D, T> {
  fn tip_key(&self) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"tip", self.genesis)
  }
  fn block_number_key(&self) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"block_number", self.genesis)
  }
  fn block_key(&self, hash: &[u8; 32]) -> Vec<u8> {
    // Since block hashes incorporate their parent, and the first parent is the genesis, this is
    // fine not incorporating the hash unless there's a hash collision
    D::key(b"tributary_blockchain", b"block", hash)
  }
  fn commit_key(&self, hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"commit", hash)
  }
  fn next_nonce_key(&self, signer: &<Ristretto as Ciphersuite>::G) -> Vec<u8> {
    D::key(
      b"tributary_blockchain",
      b"next_nonce",
      [self.genesis.as_ref(), signer.to_bytes().as_ref()].concat(),
    )
  }

  pub(crate) fn new(
    db: D,
    genesis: [u8; 32],
    participants: &[<Ristretto as Ciphersuite>::G],
  ) -> Self {
    let mut next_nonces = HashMap::new();
    for participant in participants {
      next_nonces.insert(*participant, 0);
    }

    let mut res = Self {
      db: Some(db.clone()),
      genesis,

      block_number: 0,
      tip: genesis,
      next_nonces,

      provided: ProvidedTransactions::new(db.clone(), genesis),
      mempool: Mempool::new(db, genesis),
    };

    if let Some((block_number, tip)) = {
      let db = res.db.as_ref().unwrap();
      db.get(res.block_number_key()).map(|number| (number, db.get(res.tip_key()).unwrap()))
    } {
      res.block_number = u32::from_le_bytes(block_number.try_into().unwrap());
      res.tip.copy_from_slice(&tip);
    }

    for participant in participants {
      if let Some(next_nonce) = res.db.as_ref().unwrap().get(res.next_nonce_key(participant)) {
        res.next_nonces.insert(*participant, u32::from_le_bytes(next_nonce.try_into().unwrap()));
      }
    }

    res
  }

  pub(crate) fn tip(&self) -> [u8; 32] {
    self.tip
  }

  pub(crate) fn block_number(&self) -> u32 {
    self.block_number
  }

  pub(crate) fn block(&self, block: &[u8; 32]) -> Option<Block<T>> {
    self
      .db
      .as_ref()
      .unwrap()
      .get(self.block_key(block))
      .map(|bytes| Block::<T>::read::<&[u8]>(&mut bytes.as_ref()).unwrap())
  }

  pub(crate) fn commit(&self, block: &[u8; 32]) -> Option<Vec<u8>> {
    self.db.as_ref().unwrap().get(self.commit_key(block))
  }

  pub(crate) fn add_transaction(&mut self, internal: bool, tx: T) -> bool {
    self.mempool.add(&self.next_nonces, internal, tx)
  }

  pub(crate) fn provide_transaction(&mut self, tx: T) -> Result<(), ProvidedError> {
    self.provided.provide(tx)
  }

  /// Returns the next nonce for signing, or None if they aren't a participant.
  pub(crate) fn next_nonce(&self, key: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    Some(self.next_nonces.get(&key).cloned()?.max(self.mempool.next_nonce(&key).unwrap_or(0)))
  }

  pub(crate) fn build_block(&mut self) -> Block<T> {
    let block = Block::new(
      self.tip,
      self.provided.transactions.iter().cloned().collect(),
      self.mempool.block(&self.next_nonces),
    );
    // build_block should not return invalid blocks
    self.verify_block(&block).unwrap();
    block
  }

  pub(crate) fn verify_block(&self, block: &Block<T>) -> Result<(), BlockError> {
    block.verify(
      self.genesis,
      self.tip,
      &self.provided.transactions.iter().map(Transaction::hash).collect::<Vec<_>>(),
      self.next_nonces.clone(),
    )
  }

  /// Add a block.
  pub(crate) fn add_block(&mut self, block: &Block<T>, commit: Vec<u8>) -> Result<(), BlockError> {
    self.verify_block(block)?;

    // None of the following assertions should be reachable since we verified the block

    // Take it from the Option so Rust doesn't consider self as mutably borrowed thanks to the
    // existence of the txn
    let mut db = self.db.take().unwrap();
    let mut txn = db.txn();

    self.tip = block.hash();
    txn.put(self.tip_key(), self.tip);

    self.block_number += 1;
    txn.put(self.block_number_key(), self.block_number.to_le_bytes());

    txn.put(self.block_key(&self.tip), block.serialize());
    txn.put(self.commit_key(&self.tip), commit);

    for tx in &block.transactions {
      match tx.kind() {
        TransactionKind::Provided => {
          self.provided.complete(&mut txn, tx.hash());
        }
        TransactionKind::Unsigned => {}
        TransactionKind::Signed(Signed { signer, nonce, .. }) => {
          let next_nonce = nonce + 1;
          let prev = self
            .next_nonces
            .insert(*signer, next_nonce)
            .expect("block had signed transaction from non-participant");
          if prev != *nonce {
            panic!("verified block had an invalid nonce");
          }

          txn.put(self.next_nonce_key(signer), next_nonce.to_le_bytes());

          self.mempool.remove(&tx.hash());
        }
      }
    }

    txn.commit();
    self.db = Some(db);

    Ok(())
  }
}
