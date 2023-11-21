use std::collections::{VecDeque, HashMap};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db, Get, create_db};

use scale::{Encode, Decode};

use tendermint::ext::{Network, Commit};

use crate::{
  ReadWrite, ProvidedError, ProvidedTransactions, BlockQuantityDb, LocalQuantityDb, BlockError, Block, Mempool, Transaction,
  transaction::{Signed, TransactionKind, TransactionError, Transaction as TransactionTrait},
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

create_db!(
  TributaryBlockchainDb {
    TipsDb: (genesis: [u8; 32]) -> [u8; 32],
    BlockNumberDb: (genesis: [u8; 32]) -> Vec<u8>,
    BlockDb: (genesis:  [u8; 32], hash: &[u8; 32]) -> Vec<u8>,
    BlockHashDb: (genesis: [u8; 32], block_number: u32) -> [u8; 32],
    CommitDb: (genesis: [u8; 32], block: &[u8; 32]) -> Vec<u8>,
    BlockAfterDb: (genesis: [u8; 32], hash: [u8; 32]) -> [u8; 32],
    UnsignedIncludedDb: (genesis: [u8; 32], hash: [u8; 32]) -> Vec<u8>,
    ProvidedIncludedDb: (genesis: [u8; 32], hash: [u8; 32]) -> Vec<u8>,
    NextNonceDb: (genesis: [u8; 32], hash: [u8; 32]) -> Vec<u8>
  }
);

impl<D: Db, T: TransactionTrait> Blockchain<D, T> {
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
    let self_db = res.db.as_ref().unwrap();
    if let Some((block_number, tip)) = {
      BlockNumberDb::get(self_db, genesis).map(|number| (number, TipsDb::get(self_db, genesis).unwrap()))
    } {
      res.block_number = u32::from_le_bytes(block_number.try_into().unwrap());
      res.tip.copy_from_slice(&tip);
    }

    for participant in participants {
      if let Some(next_nonce) = NextNonceDb::get(self_db, genesis, participant.to_bytes()) {
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
    BlockDb::get(db, genesis, block)
      .map(|bytes| Block::<T>::read::<&[u8]>(&mut bytes.as_ref()).unwrap())
  }

  pub(crate) fn commit(&self, block: &[u8; 32]) -> Option<Vec<u8>> {
    CommitDb::get(self.db.as_ref().unwrap(), self.genesis, block)
  }

  pub(crate) fn commit_by_block_number(&self, block: u32) -> Option<Vec<u8>> {
    CommitDb::get(self.db.as_ref().unwrap(), self.genesis, &BlockHashDb::get(self.db.as_ref().unwrap(), self.genesis, block).unwrap())
  }

  pub(crate) fn locally_provided_txs_in_block(
    db: &D,
    genesis: &[u8; 32],
    block: &[u8; 32],
    order: &str,
  ) -> bool {
    let order_bytes = order.as_bytes();
    let local = LocalQuantityDb::get(db, genesis, order_bytes).unwrap_or_default();
    let block = BlockQuantityDb::get(db, genesis, block, order_bytes).unwrap_or_default();
    local >= block
  }

  pub(crate) fn tip_from_db(db: &D, genesis: [u8; 32]) -> [u8; 32] {
    TipsDb::get(db, genesis).unwrap_or(genesis)
  }

  pub(crate) fn add_transaction<N: Network>(
    &mut self,
    internal: bool,
    tx: Transaction<T>,
    schema: N::SignatureScheme,
  ) -> Result<bool, TransactionError> {
    let db = self.db.as_ref().unwrap();
    let genesis = self.genesis;

    let commit = |block: u32| -> Option<Commit<N::SignatureScheme>> {
      let hash = BlockHashDb::get(db, genesis, block)?;
      // we must have a commit per valid hash
      let commit = CommitDb::get(db, genesis, &hash).unwrap();
      // commit has to be valid if it is coming from our db
      Some(Commit::<N::SignatureScheme>::decode(&mut commit.as_ref()).unwrap())
    };

    let unsigned_in_chain =
      |hash: [u8; 32]| UnsignedIncludedDb::get(db, self.genesis, hash).is_some();
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
      |hash: [u8; 32]| UnsignedIncludedDb::get(db, self.genesis, hash).is_some();

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
    allow_non_local_provided: bool,
  ) -> Result<(), BlockError> {
    let db = self.db.as_ref().unwrap();
    let unsigned_in_chain =
      |hash: [u8; 32]| UnsignedIncludedDb::get(db, self.genesis, hash).is_some();
    let provided_in_chain =
      |hash: [u8; 32]| ProvidedIncludedDb::get(db, self.genesis, hash).is_some();
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
      allow_non_local_provided,
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
    TipsDb::set(&mut txn, self.genesis, &self.tip);

    self.block_number += 1;
    BlockNumberDb::set(&mut txn, self.genesis, &self.block_number.to_le_bytes());

    BlockHashDb::set(&mut txn, self.genesis, self.block_number, &self.tip);

    BlockDb::set(&mut txn, self.genesis, &self.tip, &block.serialize());

    CommitDb::set(&mut txn, self.genesis, &self.tip, &commit);

    BlockAfterDb::set(&mut txn, self.genesis, block.parent(), &block.hash());

    for tx in &block.transactions {
      match tx.kind() {
        TransactionKind::Provided(order) => {
          let hash = tx.hash();
          self.provided.complete(&mut txn, order, self.tip, hash);
          ProvidedIncludedDb::set(&mut txn, self.genesis, hash, &[] as &[u8; 0]);
        }
        TransactionKind::Unsigned => {
          let hash = tx.hash();
          // Save as included on chain
          UnsignedIncludedDb::set(&mut txn, self.genesis, hash, &[] as &[u8; 0]);
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
          NextNonceDb::set(&mut txn, self.genesis, signer.to_bytes(), &next_nonce.to_le_bytes());

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