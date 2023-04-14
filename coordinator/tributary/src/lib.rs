use core::fmt::Debug;
use std::{
  sync::{Arc, RwLock},
  io,
  collections::HashMap,
};

use async_trait::async_trait;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use scale::Decode;
use futures::SinkExt;
use ::tendermint::{
  ext::{BlockNumber, Commit, Block as BlockTrait, Network},
  SignedMessageFor, SyncedBlock, SyncedBlockSender, MessageSender, TendermintMachine,
  TendermintHandle,
};

use serai_db::Db;

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

pub(crate) const TRANSACTION_MESSAGE: u8 = 0;
pub(crate) const TENDERMINT_MESSAGE: u8 = 1;

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
  async fn broadcast(&self, msg: Vec<u8>);
}

#[async_trait]
impl<P: P2p> P2p for Arc<P> {
  async fn broadcast(&self, msg: Vec<u8>) {
    (*self).broadcast(msg).await
  }
}

pub struct Tributary<D: Db, T: Transaction, P: P2p> {
  network: TendermintNetwork<D, T, P>,

  synced_block: SyncedBlockSender<TendermintNetwork<D, T, P>>,
  messages: MessageSender<TendermintNetwork<D, T, P>>,
}

impl<D: Db, T: Transaction, P: P2p> Tributary<D, T, P> {
  pub async fn new(
    db: D,
    genesis: [u8; 32],
    start_time: u64,
    key: Zeroizing<<Ristretto as Ciphersuite>::F>,
    validators: HashMap<<Ristretto as Ciphersuite>::G, u64>,
    p2p: P,
  ) -> Option<Self> {
    let validators_vec = validators.keys().cloned().collect::<Vec<_>>();

    let signer = Arc::new(Signer::new(genesis, key));
    let validators = Arc::new(Validators::new(genesis, validators)?);

    let mut blockchain = Blockchain::new(db, genesis, &validators_vec);
    let block_number = blockchain.block_number();

    let start_time = if let Some(commit) = blockchain.commit(&blockchain.tip()) {
      Commit::<Validators>::decode(&mut commit.as_ref()).unwrap().end_time
    } else {
      start_time
    };
    let proposal = TendermintBlock(blockchain.build_block().serialize());
    let blockchain = Arc::new(RwLock::new(blockchain));

    let network = TendermintNetwork { genesis, signer, validators, blockchain, p2p };

    // The genesis block is 0, so we're working on block #1
    let block_number = BlockNumber((block_number + 1).into());
    let TendermintHandle { synced_block, messages, machine } =
      TendermintMachine::new(network.clone(), block_number, start_time, proposal).await;
    tokio::task::spawn(machine.run());

    Some(Self { network, synced_block, messages })
  }

  pub fn provide_transaction(&self, tx: T) -> Result<(), ProvidedError> {
    self.network.blockchain.write().unwrap().provide_transaction(tx)
  }

  pub fn next_nonce(&self, signer: <Ristretto as Ciphersuite>::G) -> Option<u32> {
    self.network.blockchain.read().unwrap().next_nonce(signer)
  }

  // Returns if the transaction was valid.
  pub async fn add_transaction(&mut self, tx: T) -> bool {
    let mut to_broadcast = vec![TRANSACTION_MESSAGE];
    tx.write(&mut to_broadcast).unwrap();
    let res = self.network.blockchain.write().unwrap().add_transaction(true, tx);
    if res {
      self.network.p2p.broadcast(to_broadcast).await;
    }
    res
  }

  // Sync a block.
  // TODO: Since we have a static validator set, we should only need the tail commit?
  pub async fn sync_block(&mut self, block: Block<T>, commit: Vec<u8>) -> bool {
    let (tip, block_number) = {
      let blockchain = self.network.blockchain.read().unwrap();
      (blockchain.tip(), blockchain.block_number())
    };

    if block.header.parent != tip {
      return false;
    }

    let block = TendermintBlock(block.serialize());
    let Ok(commit) = Commit::<Arc<Validators>>::decode(&mut commit.as_ref()) else {
      return false;
    };
    if !self.network.verify_commit(block.id(), &commit) {
      return false;
    }

    let number = BlockNumber((block_number + 1).into());
    self.synced_block.send(SyncedBlock { number, block, commit }).await.unwrap();
    true
  }

  // Return true if the message should be rebroadcasted.
  pub async fn handle_message(&mut self, msg: Vec<u8>) -> bool {
    match msg[0] {
      TRANSACTION_MESSAGE => {
        let Ok(tx) = T::read::<&[u8]>(&mut &msg[1 ..]) else {
          return false;
        };

        // TODO: Sync mempools with fellow peers
        // Can we just rebroadcast transactions not included for at least two blocks?
        self.network.blockchain.write().unwrap().add_transaction(false, tx)
      }

      TENDERMINT_MESSAGE => {
        let Ok(msg) = SignedMessageFor::<TendermintNetwork<D, T, P>>::decode::<&[u8]>(
          &mut &msg[1 ..]
        ) else {
          return false;
        };

        // If this message isn't to form consensus on the next block, ignore it
        if msg.block().0 != (self.network.blockchain.read().unwrap().block_number() + 1).into() {
          return false;
        }

        if !msg.verify_signature(&self.network.validators) {
          return false;
        }

        self.messages.send(msg).await.unwrap();
        true
      }

      _ => false,
    }
  }
}
