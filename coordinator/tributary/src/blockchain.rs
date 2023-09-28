use std::collections::{VecDeque, HashMap};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db};

use scale::Decode;

use tendermint::ext::{Network, Commit};

use crate::{
  ReadWrite, ProvidedError, ProvidedTransactions, BlockError, Block, Mempool, Transaction,
  transaction::{Signed, TransactionKind, Transaction as TransactionTrait},
};

#[derive(Debug)]
pub(crate) struct Blockchain<D: Db, T: TransactionTrait> {
  db: Option<D>,
  genesis: [u8; 32],

  block_number: u32,
  tip: [u8; 32],
  next_nonces: HashMap<<Ristretto as Ciphersuite>::G, u32>,

  provided: ProvidedTransactions<D, T>,
  mempool: Mempool<D, T>,

  pub(crate) next_block_notifications: VecDeque<tokio::sync::oneshot::Sender<()>>,
}

impl<D: Db, T: TransactionTrait> Blockchain<D, T> {
  fn tip_key(genesis: [u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"tip", genesis)
  }
  fn block_number_key(&self) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"block_number", self.genesis)
  }
  fn block_key(genesis: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"block", [genesis, hash].concat())
  }
  fn block_hash_key(genesis: &[u8], block_number: u32) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"block_hash", [genesis, &block_number.to_le_bytes()].concat())
  }
  fn commit_key(genesis: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"commit", [genesis, hash].concat())
  }
  fn block_after_key(genesis: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"block_after", [genesis, hash].concat())
  }
  fn unsigned_included_key(genesis: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"unsigned_included", [genesis, hash].concat())
  }
  fn provided_included_key(genesis: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    D::key(b"tributary_blockchain", b"provided_included", [genesis, hash].concat())
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

      next_block_notifications: VecDeque::new(),
    };

    if let Some((block_number, tip)) = {
      let db = res.db.as_ref().unwrap();
      db.get(res.block_number_key()).map(|number| (number, db.get(Self::tip_key(genesis)).unwrap()))
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

  pub(crate) fn block_from_db(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<Block<T>> {
    db.get(Self::block_key(&genesis, block))
      .map(|bytes| Block::<T>::read::<&[u8]>(&mut bytes.as_ref()).unwrap())
  }

  pub(crate) fn commit_from_db(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<Vec<u8>> {
    db.get(Self::commit_key(&genesis, block))
  }

  pub(crate) fn block_hash_from_db(db: &D, genesis: [u8; 32], block: u32) -> Option<[u8; 32]> {
    db.get(Self::block_hash_key(&genesis, block)).map(|h| h.try_into().unwrap())
  }

  pub(crate) fn commit(&self, block: &[u8; 32]) -> Option<Vec<u8>> {
    Self::commit_from_db(self.db.as_ref().unwrap(), self.genesis, block)
  }

  pub(crate) fn block_hash(&self, block: u32) -> Option<[u8; 32]> {
    Self::block_hash_from_db(self.db.as_ref().unwrap(), self.genesis, block)
  }

  pub(crate) fn commit_by_block_number(&self, block: u32) -> Option<Vec<u8>> {
    self.commit(&self.block_hash(block)?)
  }

  pub(crate) fn block_after(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<[u8; 32]> {
    db.get(Self::block_after_key(&genesis, block)).map(|bytes| bytes.try_into().unwrap())
  }

  pub(crate) fn provided_waiting_list_empty(db: &D, genesis: [u8; 32]) -> bool {
    let key = ProvidedTransactions::<D, T>::waiting_list_key(genesis);
    #[allow(clippy::unwrap_or_default)]
    db.get(key).unwrap_or(vec![]).is_empty()
  }

  pub(crate) fn tip_from_db(db: &D, genesis: [u8; 32]) -> [u8; 32] {
    db.get(Self::tip_key(genesis)).map(|bytes| bytes.try_into().unwrap()).unwrap_or(genesis)
  }

  pub(crate) fn add_transaction<N: Network>(
    &mut self,
    internal: bool,
    tx: Transaction<T>,
    schema: N::SignatureScheme,
  ) -> bool {
    let db = self.db.as_ref().unwrap();
    let genesis = self.genesis;

    let commit = |block: u32| -> Option<Commit<N::SignatureScheme>> {
      let hash = Self::block_hash_from_db(db, genesis, block)?;
      // we must have a commit per valid hash
      let commit = Self::commit_from_db(db, genesis, &hash).unwrap();
      // commit has to be valid if it is coming from our db
      Some(Commit::<N::SignatureScheme>::decode(&mut commit.as_ref()).unwrap())
    };

    let unsigned_in_chain =
      |hash: [u8; 32]| db.get(Self::unsigned_included_key(&self.genesis, &hash)).is_some();
    self.mempool.add::<N>(&self.next_nonces, internal, tx, schema, unsigned_in_chain, commit)
  }

  pub(crate) fn provide_transaction(&mut self, tx: T) -> Result<(), ProvidedError> {
    self.provided.provide(tx)
  }

  /// Returns the next nonce for signing, or None if they aren't a participant.
  pub(crate) fn next_nonce(&self, key: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    Some(self.next_nonces.get(&key).cloned()?.max(self.mempool.next_nonce(&key).unwrap_or(0)))
  }

  pub(crate) fn build_block<N: Network>(&mut self, schema: N::SignatureScheme) -> Block<T> {
    let db = self.db.as_ref().unwrap();
    let unsigned_in_chain =
      |hash: [u8; 32]| db.get(Self::unsigned_included_key(&self.genesis, &hash)).is_some();

    let block = Block::new(
      self.tip,
      self.provided.transactions.values().flatten().cloned().collect(),
      self.mempool.block(&self.next_nonces, unsigned_in_chain),
    );
    // build_block should not return invalid blocks
    self.verify_block::<N>(&block, schema, false).unwrap();
    block
  }

  pub(crate) fn verify_block<N: Network>(
    &self,
    block: &Block<T>,
    schema: N::SignatureScheme,
    ignore_non_local_provided: bool,
  ) -> Result<(), BlockError> {
    let db = self.db.as_ref().unwrap();
    let unsigned_in_chain =
      |hash: [u8; 32]| db.get(Self::unsigned_included_key(&self.genesis, &hash)).is_some();
    let provided_in_chain =
      |hash: [u8; 32]| db.get(Self::provided_included_key(&self.genesis, &hash)).is_some();
    let commit = |block: u32| -> Option<Commit<N::SignatureScheme>> {
      let commit = self.commit_by_block_number(block)?;
      // commit has to be valid if it is coming from our db
      Some(Commit::<N::SignatureScheme>::decode(&mut commit.as_ref()).unwrap())
    };
    block.verify::<N>(
      self.genesis,
      self.tip,
      self.provided.transactions.clone(),
      self.next_nonces.clone(),
      schema,
      &commit,
      unsigned_in_chain,
      provided_in_chain,
      ignore_non_local_provided,
    )
  }

  /// Add a block.
  pub(crate) fn add_block<N: Network>(
    &mut self,
    block: &Block<T>,
    commit: Vec<u8>,
    schema: N::SignatureScheme,
  ) -> Result<(), BlockError> {
    self.verify_block::<N>(block, schema, true)?;

    log::info!(
      "adding block {} to tributary {} with {} TXs",
      hex::encode(block.hash()),
      hex::encode(self.genesis),
      block.transactions.len(),
    );

    // None of the following assertions should be reachable since we verified the block

    // Take it from the Option so Rust doesn't consider self as mutably borrowed thanks to the
    // existence of the txn
    let mut db = self.db.take().unwrap();
    let mut txn = db.txn();

    self.tip = block.hash();
    txn.put(Self::tip_key(self.genesis), self.tip);

    self.block_number += 1;
    txn.put(self.block_number_key(), self.block_number.to_le_bytes());

    txn.put(Self::block_hash_key(&self.genesis, self.block_number), self.tip);

    txn.put(Self::block_key(&self.genesis, &self.tip), block.serialize());
    txn.put(Self::commit_key(&self.genesis, &self.tip), commit);

    txn.put(Self::block_after_key(&self.genesis, &block.parent()), block.hash());

    for tx in &block.transactions {
      match tx.kind() {
        TransactionKind::Provided(order) => {
          let hash = tx.hash();
          self.provided.complete(&mut txn, order, hash);
          txn.put(Self::provided_included_key(&self.genesis, &hash), []);
        }
        TransactionKind::Unsigned => {
          let hash = tx.hash();
          // Save as included on chain
          txn.put(Self::unsigned_included_key(&self.genesis, &hash), []);
          // remove from the mempool
          self.mempool.remove(&hash);
        }
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

    for tx in self.next_block_notifications.drain(..) {
      let _ = tx.send(());
    }

    Ok(())
  }
}
