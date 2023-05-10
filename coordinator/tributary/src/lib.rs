use core::{marker::PhantomData, fmt::Debug};
use std::{sync::Arc, io};

use async_trait::async_trait;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use scale::Decode;
use futures::{StreamExt, SinkExt};
use ::tendermint::{
  ext::{BlockNumber, Commit, Block as BlockTrait, Network},
  SignedMessageFor, SyncedBlock, SyncedBlockSender, SyncedBlockResultReceiver, MessageSender,
  TendermintMachine, TendermintHandle,
};

use serai_db::Db;

use tokio::sync::RwLock;

mod merkle;
pub(crate) use merkle::*;

mod transaction;
pub use transaction::*;

mod provided;
pub(crate) use provided::*;
pub use provided::ProvidedError;

mod block;
pub use block::*;

mod blockchain;
pub(crate) use blockchain::*;

mod mempool;
pub(crate) use mempool::*;

mod tendermint;
pub(crate) use crate::tendermint::*;

#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// Size limit for an individual transaction.
pub const TRANSACTION_SIZE_LIMIT: usize = 50_000;
/// Amount of transactions a single account may have in the mempool.
pub const ACCOUNT_MEMPOOL_LIMIT: u32 = 50;
/// Block size limit.
// This targets a growth limit of roughly 5 GB a day, under load, in order to prevent a malicious
// participant from flooding disks and causing out of space errors in order processes.
pub const BLOCK_SIZE_LIMIT: usize = 350_000;

pub(crate) const TENDERMINT_MESSAGE: u8 = 0;
pub(crate) const BLOCK_MESSAGE: u8 = 1;
pub(crate) const TRANSACTION_MESSAGE: u8 = 2;

/// An item which can be read and written.
pub trait ReadWrite: Sized {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;

  fn serialize(&self) -> Vec<u8> {
    // BlockHeader is 64 bytes and likely the smallest item in this system
    let mut buf = Vec::with_capacity(64);
    self.write(&mut buf).unwrap();
    buf
  }
}

#[async_trait]
pub trait P2p: 'static + Send + Sync + Clone + Debug {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>);
}

#[async_trait]
impl<P: P2p> P2p for Arc<P> {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    (*self).broadcast(genesis, msg).await
  }
}

#[derive(Clone)]
pub struct Tributary<D: Db, T: Transaction, P: P2p> {
  db: D,

  genesis: [u8; 32],
  network: TendermintNetwork<D, T, P>,

  synced_block: SyncedBlockSender<TendermintNetwork<D, T, P>>,
  synced_block_result: Arc<RwLock<SyncedBlockResultReceiver>>,
  messages: Arc<RwLock<MessageSender<TendermintNetwork<D, T, P>>>>,
}

impl<D: Db, T: Transaction, P: P2p> Tributary<D, T, P> {
  pub async fn new(
    db: D,
    genesis: [u8; 32],
    start_time: u64,
    key: Zeroizing<<Ristretto as Ciphersuite>::F>,
    validators: Vec<(<Ristretto as Ciphersuite>::G, u64)>,
    p2p: P,
  ) -> Option<Self> {
    let validators_vec = validators.iter().map(|validator| validator.0).collect::<Vec<_>>();

    let signer = Arc::new(Signer::new(genesis, key));
    let validators = Arc::new(Validators::new(genesis, validators)?);

    let mut blockchain = Blockchain::new(db.clone(), genesis, &validators_vec);
    let block_number = BlockNumber(blockchain.block_number().into());

    let start_time = if let Some(commit) = blockchain.commit(&blockchain.tip()) {
      Commit::<Validators>::decode(&mut commit.as_ref()).unwrap().end_time
    } else {
      start_time
    };
    let proposal = TendermintBlock(blockchain.build_block().serialize());
    let blockchain = Arc::new(RwLock::new(blockchain));

    let network = TendermintNetwork { genesis, signer, validators, blockchain, p2p };

    let TendermintHandle { synced_block, synced_block_result, messages, machine } =
      TendermintMachine::new(network.clone(), block_number, start_time, proposal).await;
    tokio::task::spawn(machine.run());

    Some(Self {
      db,
      genesis,
      network,
      synced_block,
      synced_block_result: Arc::new(RwLock::new(synced_block_result)),
      messages: Arc::new(RwLock::new(messages)),
    })
  }

  pub fn block_time() -> u32 {
    TendermintNetwork::<D, T, P>::block_time()
  }

  pub fn genesis(&self) -> [u8; 32] {
    self.genesis
  }

  pub async fn block_number(&self) -> u32 {
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

  pub async fn next_nonce(&self, signer: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.network.blockchain.read().await.next_nonce(signer)
  }

  // Returns if the transaction was valid.
  // Safe to be &self since the only meaningful usage of self is self.network.blockchain which
  // successfully acquires its own write lock
  pub async fn add_transaction(&self, tx: T) -> bool {
    let mut to_broadcast = vec![TRANSACTION_MESSAGE];
    tx.write(&mut to_broadcast).unwrap();
    let res = self.network.blockchain.write().await.add_transaction(true, tx);
    if res {
      self.network.p2p.broadcast(self.genesis, to_broadcast).await;
    }
    res
  }

  // Sync a block.
  // TODO: Since we have a static validator set, we should only need the tail commit?
  pub async fn sync_block(&mut self, block: Block<T>, commit: Vec<u8>) -> bool {
    let mut result = self.synced_block_result.write().await;

    let (tip, block_number) = {
      let blockchain = self.network.blockchain.read().await;
      (blockchain.tip(), blockchain.block_number())
    };

    if block.header.parent != tip {
      log::debug!("told to sync a block whose parent wasn't our tip");
      return false;
    }

    let block = TendermintBlock(block.serialize());
    let mut commit_ref = commit.as_ref();
    let Ok(commit) = Commit::<Arc<Validators>>::decode(&mut commit_ref) else {
      log::error!("sent an invalidly serialized commit");
      return false;
    };
    // Storage DoS vector. We *could* truncate to solely the relevant portion, trying to save this,
    // yet then we'd have to test the truncation was performed correctly.
    if !commit_ref.is_empty() {
      log::error!("sent an commit with additional data after it");
      return false;
    }
    if !self.network.verify_commit(block.id(), &commit) {
      log::error!("sent an invalid commit");
      return false;
    }

    let number = BlockNumber((block_number + 1).into());
    self.synced_block.send(SyncedBlock { number, block, commit }).await.unwrap();
    result.next().await.unwrap()
  }

  // Return true if the message should be rebroadcasted.
  pub async fn handle_message(&mut self, msg: &[u8]) -> bool {
    match msg.first() {
      Some(&TRANSACTION_MESSAGE) => {
        let Ok(tx) = T::read::<&[u8]>(&mut &msg[1 ..]) else {
          log::error!("received invalid transaction message");
          return false;
        };

        // TODO: Sync mempools with fellow peers
        // Can we just rebroadcast transactions not included for at least two blocks?
        let res = self.network.blockchain.write().await.add_transaction(false, tx);
        log::debug!("received transaction message. valid new transaction: {res}");
        res
      }

      Some(&TENDERMINT_MESSAGE) => {
        let Ok(msg) = SignedMessageFor::<TendermintNetwork<D, T, P>>::decode::<&[u8]>(
          &mut &msg[1 ..]
        ) else {
          log::error!("received invalid tendermint message");
          return false;
        };

        self.messages.write().await.send(msg).await.unwrap();
        false
      }

      Some(&BLOCK_MESSAGE) => {
        let mut msg_ref = &msg[1 ..];
        let Ok(block) = Block::<T>::read(&mut msg_ref) else {
          log::error!("received invalid block message");
          return false;
        };
        let commit = msg[(msg.len() - msg_ref.len()) ..].to_vec();
        if self.sync_block(block, commit).await {
          log::debug!("synced block over p2p net instead of building the commit ourselves");
        }
        false
      }

      _ => false,
    }
  }
}

#[derive(Clone)]
pub struct TributaryReader<D: Db, T: Transaction>(D, [u8; 32], PhantomData<T>);
impl<D: Db, T: Transaction> TributaryReader<D, T> {
  pub fn genesis(&self) -> [u8; 32] {
    self.1
  }
  // Since these values are static, they can be safely read from the database without lock
  // acquisition
  pub fn block(&self, hash: &[u8; 32]) -> Option<Block<T>> {
    Blockchain::<D, T>::block_from_db(&self.0, self.1, hash)
  }
  pub fn commit(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
    Blockchain::<D, T>::commit_from_db(&self.0, self.1, hash)
  }
  pub fn parsed_commit(&self, hash: &[u8; 32]) -> Option<Commit<Validators>> {
    self.commit(hash).map(|commit| Commit::<Validators>::decode(&mut commit.as_ref()).unwrap())
  }
  pub fn block_after(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
    Blockchain::<D, T>::block_after(&self.0, self.1, hash)
  }
  pub fn time_of_block(&self, hash: &[u8; 32]) -> Option<u64> {
    self
      .commit(hash)
      .map(|commit| Commit::<Validators>::decode(&mut commit.as_ref()).unwrap().end_time)
  }
}
