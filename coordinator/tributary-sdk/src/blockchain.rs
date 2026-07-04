use core::num::NonZero;
use std::collections::{VecDeque, HashMap};

use dalek_ff_group::Ristretto;
use ciphersuite::{group::GroupEncoding as _, *};

use serai_db::{Get as _, DbTxn as _, Db};

use tendermint::{SignatureScheme, Blockchain as BlockchainT};

use crate::{
  ReadWrite as _, ProvidedError, ProvidedTransactions, BlockError, Block, Mempool, Transaction,
  transaction::{Signed, TransactionKind, TransactionError, Transaction as TransactionTrait},
};

#[derive(Debug)]
pub(crate) struct Blockchain<D: Db, T: TransactionTrait> {
  db: Option<D>,
  genesis: [u8; 32],

  block_number: u64,
  tip: [u8; 32],
  participants: HashMap<[u8; 32], NonZero<u16>>,

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
  fn block_hash_key(genesis: &[u8], block_number: u64) -> Vec<u8> {
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
  fn next_nonce_key(
    genesis: &[u8; 32],
    signer: &<Ristretto as WrappedGroup>::G,
    order: &[u8],
  ) -> Vec<u8> {
    D::key(
      b"tributary_blockchain",
      b"next_nonce",
      [genesis.as_slice(), signer.to_bytes().as_slice(), order].concat(),
    )
  }

  pub(crate) fn new(
    db: D,
    genesis: [u8; 32],
    participants: HashMap<[u8; 32], NonZero<u16>>,
  ) -> Self {
    let mut res = Self {
      db: Some(db.clone()),
      genesis,
      participants,

      block_number: 0,
      tip: genesis,

      provided: ProvidedTransactions::new(db.clone(), genesis),
      mempool: Mempool::new(db, genesis),

      next_block_notifications: VecDeque::new(),
    };

    if let Some((block_number, tip)) = {
      let db = res.db.as_ref().unwrap();
      db.get(res.block_number_key()).map(|number| (number, db.get(Self::tip_key(genesis)).unwrap()))
    } {
      res.block_number = u64::from_le_bytes(block_number.try_into().unwrap());
      res.tip.copy_from_slice(&tip);
    }

    res
  }

  pub(crate) fn tip(&self) -> [u8; 32] {
    self.tip
  }

  pub(crate) fn block_number(&self) -> u64 {
    self.block_number
  }

  pub(crate) fn block_from_db(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<Block<T>> {
    db.get(Self::block_key(&genesis, block))
      .map(|bytes| Block::<T>::read(bytes.as_slice()).unwrap())
  }

  pub(crate) fn commit_from_db(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<Vec<u8>> {
    db.get(Self::commit_key(&genesis, block))
  }

  pub(crate) fn block_after(db: &D, genesis: [u8; 32], block: &[u8; 32]) -> Option<[u8; 32]> {
    db.get(Self::block_after_key(&genesis, block)).map(|bytes| bytes.try_into().unwrap())
  }

  pub(crate) fn locally_provided_txs_in_block(
    db: &D,
    genesis: &[u8; 32],
    block: &[u8; 32],
    order: &str,
  ) -> bool {
    let local_key = ProvidedTransactions::<D, T>::locally_provided_quantity_key(genesis, order);
    let local =
      db.get(local_key).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap())).unwrap_or(0);
    let block_key =
      ProvidedTransactions::<D, T>::block_provided_quantity_key(genesis, block, order);
    let block =
      db.get(block_key).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap())).unwrap_or(0);

    local >= block
  }

  pub(crate) fn tip_from_db(db: &D, genesis: [u8; 32]) -> [u8; 32] {
    db.get(Self::tip_key(genesis)).map(|bytes| bytes.try_into().unwrap()).unwrap_or(genesis)
  }

  pub(crate) fn add_transaction<
    N: BlockchainT<
      Validator = [u8; 32],
      ValidatorSet = HashMap<[u8; 32], NonZero<u16>>,
      SignatureScheme: SignatureScheme<Signature = [u8; 64]>,
    >,
  >(
    &mut self,
    internal: bool,
    tx: Transaction<T>,
    schema: &N::SignatureScheme,
  ) -> Result<bool, TransactionError> {
    let db = self.db.as_ref().unwrap();

    let unsigned_in_chain =
      |hash: [u8; 32]| db.get(Self::unsigned_included_key(&self.genesis, &hash)).is_some();

    self.mempool.add::<N, _>(
      |signer, order| {
        self.participants.contains_key(&signer.to_bytes()).then(|| {
          db.get(Self::next_nonce_key(&self.genesis, &signer, &order))
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .unwrap_or(0)
        })
      },
      internal,
      tx,
      &self.participants,
      schema,
      unsigned_in_chain,
    )
  }

  pub(crate) fn provide_transaction(&mut self, tx: T) -> Result<(), ProvidedError> {
    self.provided.provide(tx)
  }

  pub(crate) fn next_nonce(
    &self,
    signer: &<Ristretto as WrappedGroup>::G,
    order: &[u8],
  ) -> Option<u32> {
    if let Some(next_nonce) = self.mempool.next_nonce_in_mempool(signer, order.to_vec()) {
      return Some(next_nonce);
    }
    self.participants.contains_key(&signer.to_bytes()).then(|| {
      self
        .db
        .as_ref()
        .unwrap()
        .get(Self::next_nonce_key(&self.genesis, signer, order))
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .unwrap_or(0)
    })
  }

  pub(crate) fn build_block<
    N: BlockchainT<
      Validator = [u8; 32],
      ValidatorSet = HashMap<[u8; 32], NonZero<u16>>,
      SignatureScheme: SignatureScheme<Signature = [u8; 64]>,
    >,
  >(
    &mut self,
    schema: &N::SignatureScheme,
  ) -> Block<T> {
    let block = Block::new(
      self.tip,
      self.provided.transactions.values().flatten().cloned().collect(),
      self.mempool.block(),
    );
    // build_block should not return invalid blocks
    self.verify_block::<N>(&block, schema, false).unwrap();
    block
  }

  pub(crate) fn verify_block<
    N: BlockchainT<
      Validator = [u8; 32],
      ValidatorSet = HashMap<[u8; 32], NonZero<u16>>,
      SignatureScheme: SignatureScheme<Signature = [u8; 64]>,
    >,
  >(
    &self,
    block: &Block<T>,
    schema: &N::SignatureScheme,
    allow_non_local_provided: bool,
  ) -> Result<(), BlockError> {
    let db = self.db.as_ref().unwrap();
    let provided_or_unsigned_in_chain = |hash: [u8; 32]| {
      db.get(Self::unsigned_included_key(&self.genesis, &hash)).is_some() ||
        db.get(Self::provided_included_key(&self.genesis, &hash)).is_some()
    };

    let mut txn_db = db.clone();
    let mut txn = txn_db.txn();
    let res = block.verify::<N, _>(
      self.genesis,
      self.tip,
      self.provided.transactions.clone(),
      &mut |signer, order| {
        self.participants.contains_key(&signer.to_bytes()).then(|| {
          let key = Self::next_nonce_key(&self.genesis, signer, order);
          let next = txn
            .get(&key)
            .map(|next_nonce| u32::from_le_bytes(next_nonce.try_into().unwrap()))
            .unwrap_or(0);
          txn.put(key, (next + 1).to_le_bytes());
          next
        })
      },
      &self.participants,
      schema,
      provided_or_unsigned_in_chain,
      allow_non_local_provided,
    );
    // Drop this TXN's changes as we're solely verifying the block
    drop(txn);
    res
  }

  /// Add a block.
  pub(crate) fn add_block<
    N: BlockchainT<
      Validator = [u8; 32],
      ValidatorSet = HashMap<[u8; 32], NonZero<u16>>,
      SignatureScheme: SignatureScheme<Signature = [u8; 64]>,
    >,
  >(
    &mut self,
    block: &Block<T>,
    commit: Vec<u8>,
    schema: &N::SignatureScheme,
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
          self.provided.complete(&mut txn, order, self.tip, hash);
          txn.put(Self::provided_included_key(&self.genesis, &hash), []);
        }
        TransactionKind::Unsigned => {
          let hash = tx.hash();
          // Save as included on chain
          txn.put(Self::unsigned_included_key(&self.genesis, &hash), []);
          // remove from the mempool
          self.mempool.remove(&hash);
        }
        TransactionKind::Signed(order, Signed { signer, nonce, .. }) => {
          let next_nonce = nonce + 1;
          txn.put(Self::next_nonce_key(&self.genesis, &signer, &order), next_nonce.to_le_bytes());
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
