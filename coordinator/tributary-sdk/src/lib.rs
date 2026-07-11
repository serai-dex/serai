#![allow(clippy::std_instead_of_alloc)]

use core::{marker::PhantomData, fmt::Debug, future::Future, num::NonZero};
use std::{sync::Arc, io, time::Instant};

use zeroize::Zeroizing;

use borsh::BorshDeserialize as _;

use ciphersuite::*;
use dalek_ff_group::Ristretto;

use ::tendermint::{Block as _, Commit, Tendermint, TendermintHandle};

use ::tendermint::{Blockchain as _, MessageFor};
pub use ::tendermint::SlashReason;

use serai_db::Db;

use tokio::sync::RwLock;

mod merkle;
pub(crate) use merkle::*;

pub mod transaction;
pub use transaction::{TransactionError, Signed, TransactionKind, Transaction as TransactionTrait};

use crate::tendermint::tx::TendermintTx;

mod provided;
pub(crate) use provided::*;
pub use provided::ProvidedError;

mod block;
pub use block::*;

mod blockchain;
pub(crate) use blockchain::*;

mod mempool;
pub(crate) use mempool::*;

pub mod tendermint;
pub(crate) use crate::tendermint::*;

/* TODO
#[cfg(any(test, feature = "tests"))]
pub mod tests;
*/

/// Size limit for an individual transaction.
// This needs to be big enough to participate in a 101-of-150 eVRF DKG with each element taking
// `MAX_KEY_LEN`. This also needs to be big enough to pariticpate in signing 520 Bitcoin inputs
// with 49 key shares, and signing 120 Monero inputs with 49 key shares.
// TODO: Add a test for these properties
pub const TRANSACTION_SIZE_LIMIT: usize = 2_000_000;
/// Amount of transactions a single account may have in the mempool.
pub const ACCOUNT_MEMPOOL_LIMIT: u32 = 50;
/// Block size limit.
// This targets a growth limit of roughly 30 GB a day, under load, in order to prevent a malicious
// participant from flooding disks and causing out of space errors in order processes.
// TODO: Slash reasons for sufficiently large validator sets may exceed this
pub const BLOCK_SIZE_LIMIT: usize = 2_001_000;

pub(crate) const TENDERMINT_MESSAGE: u8 = 0;
pub(crate) const TRANSACTION_MESSAGE: u8 = 1;

#[expect(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Transaction<T: TransactionTrait> {
  Tendermint(TendermintTx),
  Application(T),
}

impl<T: TransactionTrait> ReadWrite for Transaction<T> {
  fn read(mut reader: impl io::Read) -> io::Result<Self> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;
    match kind[0] {
      0 => {
        let tx = TendermintTx::read(reader)?;
        Ok(Transaction::Tendermint(tx))
      }
      1 => {
        let tx = T::read(reader)?;
        Ok(Transaction::Application(tx))
      }
      _ => Err(io::Error::other("invalid transaction type")),
    }
  }
  fn write(&self, mut writer: impl io::Write) -> io::Result<()> {
    match self {
      Transaction::Tendermint(tx) => {
        writer.write_all(&[0])?;
        tx.write(writer)
      }
      Transaction::Application(tx) => {
        writer.write_all(&[1])?;
        tx.write(writer)
      }
    }
  }
}

impl<T: TransactionTrait> Transaction<T> {
  pub fn hash(&self) -> [u8; 32] {
    match self {
      Transaction::Tendermint(tx) => tx.hash(),
      Transaction::Application(tx) => tx.hash(),
    }
  }

  pub fn kind(&self) -> TransactionKind {
    match self {
      Transaction::Tendermint(tx) => tx.kind(),
      Transaction::Application(tx) => tx.kind(),
    }
  }
}

/// An item which can be read and written.
pub trait ReadWrite: Sized {
  fn read(reader: impl io::Read) -> io::Result<Self>;
  fn write(&self, writer: impl io::Write) -> io::Result<()>;

  fn serialize(&self) -> Vec<u8> {
    // BlockHeader is 64 bytes and likely the smallest item in this system
    let mut buf = Vec::with_capacity(64);
    self.write(&mut buf).unwrap();
    buf
  }
}

pub trait P2p: 'static + Send + Sync + Clone {
  /// Broadcast a message to all other members of the Tributary with the specified genesis.
  ///
  /// The Tributary will re-broadcast consensus messages on a fixed interval to ensure they aren't
  /// prematurely dropped from the P2P layer. THe P2P layer SHOULD perform content-based
  /// deduplication to ensure a sane amount of load.
  fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) -> impl Send + Future<Output = ()>;
}

impl<P: P2p> P2p for Arc<P> {
  fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) -> impl Send + Future<Output = ()> {
    P::broadcast(self, genesis, msg)
  }
}

#[derive(Clone)]
pub struct Tributary<D: Db, T: TransactionTrait, P: P2p> {
  db: D,

  genesis: [u8; 32],
  network: TendermintNetwork<D, T, P>,

  handle: Arc<RwLock<TendermintHandle<TendermintNetwork<D, T, P>>>>,
}

impl<D: Db, T: TransactionTrait, P: P2p> Tributary<D, T, P> {
  pub async fn new(
    db: D,
    genesis: [u8; 32],
    key: Zeroizing<<Ristretto as WrappedGroup>::F>,
    validators: Vec<(<Ristretto as WrappedGroup>::G, NonZero<u16>)>,
    p2p: P,
  ) -> Option<Self> {
    log::info!("new Tributary with genesis {}", hex::encode(genesis));

    let signer = Signer::new(genesis, key);
    let validators = Validators::new(genesis, validators)?;

    let mut blockchain = Blockchain::new(db.clone(), genesis, validators.weights().clone());

    let proposal = TendermintBlock(
      blockchain.build_block::<TendermintNetwork<D, T, P>>(&validators).serialize(),
    );
    let blockchain = Arc::new(RwLock::new(blockchain));

    let network =
      TendermintNetwork { genesis, last_addition: Instant::now(), validators, blockchain, p2p };

    let (handle, process) =
      Tendermint::process(network.clone(), signer, db.clone(), network.clone(), proposal).await;
    let handle = Arc::new(RwLock::new(handle));
    tokio::spawn(process);

    Some(Self { db, genesis, network, handle })
  }

  pub fn genesis(&self) -> [u8; 32] {
    self.genesis
  }

  pub async fn block_number(&self) -> u64 {
    self.network.blockchain.read().await.block_number()
  }
  pub async fn tip(&self) -> [u8; 32] {
    self.network.blockchain.read().await.tip()
  }

  pub fn reader(&self) -> TributaryReader<D, T> {
    TributaryReader(self.db.clone(), self.genesis, PhantomData)
  }

  pub async fn provide_transaction(&self, tx: T) -> Result<(), ProvidedError> {
    self.network.blockchain.write().await.provide_transaction(tx)
  }

  pub async fn next_nonce(
    &self,
    signer: &<Ristretto as WrappedGroup>::G,
    order: &[u8],
  ) -> Option<u32> {
    self.network.blockchain.read().await.next_nonce(signer, order)
  }

  // Returns Ok(true) if new, Ok(false) if an already present unsigned, or the error.
  // Safe to be &self since the only meaningful usage of self is self.network.blockchain which
  // successfully acquires its own write lock
  pub async fn add_transaction(&self, tx: T) -> Result<bool, TransactionError> {
    let tx = Transaction::Application(tx);
    let mut to_broadcast = vec![TRANSACTION_MESSAGE];
    tx.write(&mut to_broadcast).unwrap();
    let res = self.network.blockchain.write().await.add_transaction::<TendermintNetwork<D, T, P>>(
      true,
      tx,
      self.network.signature_scheme(),
    );
    if res == Ok(true) {
      self.network.p2p.broadcast(self.genesis, to_broadcast).await;
    }
    res
  }

  // Sync a block.
  // TODO: Since we have a static validator set, we should only need the tail commit?
  pub async fn sync_block(&self, block: Block<T>, commit: Vec<u8>) -> bool {
    let tip = self.network.blockchain.read().await.tip();

    if block.header.parent != tip {
      log::debug!("told to sync a block whose parent wasn't our tip");
      return false;
    }

    // Verify the block body corresponds to the header
    {
      let Block { header, transactions } = &block;
      if merkle(&transactions.iter().map(Transaction::hash).collect::<Vec<_>>()) !=
        header.transactions
      {
        log::error!("sent a block with a distinct body than its header commits to");
        return false;
      }
    }

    let block = TendermintBlock(block.serialize());
    let mut commit_ref = commit.as_slice();
    let Ok(commit) = Commit::<Validators>::deserialize_reader(&mut commit_ref) else {
      log::error!("sent an invalidly serialized commit");
      return false;
    };
    // Storage DoS vector. We *could* truncate to solely the relevant portion, trying to save this,
    // yet then we'd have to test the truncation was performed correctly.
    if !commit_ref.is_empty() {
      log::error!("sent an commit with additional data after it");
      return false;
    }
    if !commit.verify(
      self.network.validator_set(),
      self.network.signature_scheme(),
      self.genesis,
      block.hash(),
    ) {
      log::error!("sent an invalid commit");
      return false;
    }

    self.handle.write().await.sync(block, commit).await.unwrap();
    true
  }

  // Return true if the message should be rebroadcasted.
  pub async fn handle_message(&self, msg: &[u8]) -> bool {
    match msg.first() {
      Some(&TRANSACTION_MESSAGE) => {
        let Ok(tx) = Transaction::read(&msg[1 ..]) else {
          log::error!("received invalid transaction message");
          return false;
        };

        // TODO: Sync mempools with fellow peers
        // Can we just rebroadcast transactions not included for at least two blocks?
        let res =
          self.network.blockchain.write().await.add_transaction::<TendermintNetwork<D, T, P>>(
            false,
            tx,
            self.network.signature_scheme(),
          );
        log::debug!("received transaction message. valid new transaction: {res:?}");
        res == Ok(true)
      }

      Some(&TENDERMINT_MESSAGE) => {
        let Ok(msg) = MessageFor::<TendermintNetwork<D, T, P>>::deserialize_reader(&mut &msg[1 ..])
        else {
          log::error!("received invalid tendermint message");
          return false;
        };

        self.handle.write().await.message(msg).await.unwrap();
        false
      }

      _ => false,
    }
  }

  /// Get a Future which will resolve once the next block has been added.
  pub async fn next_block_notification(
    &self,
  ) -> impl Send + Sync + Future<Output = Result<(), impl Send + Sync + core::fmt::Debug>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    self.network.blockchain.write().await.next_block_notifications.push_back(tx);
    rx
  }
}

#[derive(Clone)]
pub struct TributaryReader<D: Db, T: TransactionTrait>(D, [u8; 32], PhantomData<T>);
impl<D: Db, T: TransactionTrait> TributaryReader<D, T> {
  pub fn genesis(&self) -> [u8; 32] {
    self.1
  }

  // Since these values are static once set, they can be safely read from the database without lock
  // acquisition
  pub fn block(&self, hash: &[u8; 32]) -> Option<Block<T>> {
    Blockchain::<D, T>::block_from_db(&self.0, self.1, hash)
  }
  pub fn commit(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
    Blockchain::<D, T>::commit_from_db(&self.0, self.1, hash)
  }
  pub fn parsed_commit(&self, hash: &[u8; 32]) -> Option<Commit<Validators>> {
    self
      .commit(hash)
      .map(|commit| Commit::<Validators>::deserialize_reader(&mut commit.as_slice()).unwrap())
  }
  pub fn block_after(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
    Blockchain::<D, T>::block_after(&self.0, self.1, hash)
  }

  pub fn locally_provided_txs_in_block(&self, hash: &[u8; 32], order: &str) -> bool {
    Blockchain::<D, T>::locally_provided_txs_in_block(&self.0, &self.1, hash, order)
  }

  // This isn't static, yet can be read with only minor discrepancy risks
  pub fn tip(&self) -> [u8; 32] {
    Blockchain::<D, T>::tip_from_db(&self.0, self.1)
  }
}
