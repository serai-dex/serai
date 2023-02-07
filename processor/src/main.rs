use core::fmt::Debug;
use std::{
  pin::Pin,
  sync::{Arc, RwLock},
  task::{Poll, Context},
  future::Future,
  collections::HashMap,
};

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use serai_primitives::WithAmount;
use tokens_primitives::OutInstruction;

use messages::{CoordinatorMessage, ProcessorMessage, substrate};

mod coin;
use coin::{Block, Coin, Bitcoin, Monero};

mod key_gen;
use key_gen::{KeyGenOrder, KeyGenEvent, KeyGen};

mod signer;
use signer::{SignerOrder, SignerEvent, Signer, SignerHandle};

mod scanner;
use scanner::{ScannerOrder, ScannerEvent, Scanner};

mod scheduler;
use scheduler::Scheduler;

#[cfg(test)]
mod tests;

pub trait Db: 'static + Send + Sync + Clone + Debug {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
  fn del(&mut self, key: impl AsRef<[u8]>);
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  data: Option<Vec<u8>>,
  amount: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan<C: Coin> {
  pub inputs: Vec<C::Output>,
  pub payments: Vec<Payment<C>>,
  pub change: bool,
}

// Generate a static additional key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, to support protocols which use multiple secondary keys
// Presumably a view key
pub(crate) fn additional_key<C: Coin>(k: u64) -> <C::Curve as Ciphersuite>::F {
  <C::Curve as Ciphersuite>::hash_to_F(
    b"Serai DEX Additional Key",
    &[C::ID.as_bytes(), &k.to_le_bytes()].concat(),
  )
}

// TODO: Replace this with RocksDB
#[derive(Clone, Debug)]
struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl Db for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.write().unwrap().insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.0.write().unwrap().remove(key.as_ref());
  }
}

struct SignerMessageFuture<'a, C: Coin>(&'a mut HashMap<Vec<u8>, SignerHandle<C>>);
impl<'a, C: Coin> Future for SignerMessageFuture<'a, C> {
  type Output = (Vec<u8>, SignerEvent<C>);
  fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
    for (key, signer) in self.0.iter_mut() {
      match signer.events.poll_recv(ctx) {
        Poll::Ready(event) => return Poll::Ready((key.clone(), event.unwrap())),
        Poll::Pending => {}
      }
    }
    Poll::Pending
  }
}

async fn run<C: Coin, D: Db>(db: D, coin: C) {
  let mut key_gen = KeyGen::<C::Curve, _>::new(db.clone());
  let (mut scanner, active_keys) = Scanner::new(coin.clone(), db.clone());

  let mut schedulers = HashMap::<Vec<u8>, Scheduler<C>>::new();
  let mut signers = HashMap::new();

  for key in &active_keys {
    // TODO: Load existing schedulers

    signers.insert(
      key.to_bytes().as_ref().to_vec(),
      Signer::new(db.clone(), coin.clone(), key_gen.keys(key)),
    );
    // TODO: Re-issue SignTransaction orders
  }

  let track_key = |schedulers: &mut HashMap<_, _>, activation_number, key| {
    scanner.orders.send(ScannerOrder::RotateKey { activation_number, key }).unwrap();
    schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::<C>::new(key));
  };

  let (to_coordinator, _fake_coordinator_recv) =
    tokio::sync::mpsc::unbounded_channel::<ProcessorMessage>();
  let (_fake_coordinator_send, mut from_coordinator) =
    tokio::sync::mpsc::unbounded_channel::<CoordinatorMessage>();

  loop {
    tokio::select! {
      msg = from_coordinator.recv() => {
        match msg.expect("Coordinator channel was dropped. Shutting down?") {
          CoordinatorMessage::KeyGen(msg) => {
            key_gen.orders.send(KeyGenOrder::CoordinatorMessage(msg)).unwrap()
          },
          CoordinatorMessage::Sign(msg) => {
            signers[msg.key()].orders.send(SignerOrder::CoordinatorMessage(msg)).unwrap()
          },
          CoordinatorMessage::Substrate(
            substrate::CoordinatorMessage::BlockAcknowledged { key, block }
          ) => {
            let mut block_id = <C::Block as Block>::Id::default();
            block_id.as_mut().copy_from_slice(&block);

            let scheduler =
              schedulers
                .get_mut(&key)
                .expect("key we don't have a scheduler for acknowledged a block");
            let plans = scheduler.add_outputs(scanner.outputs(&key, &block_id));
            todo!(); // Handle plans
          }
          CoordinatorMessage::Substrate(substrate::CoordinatorMessage::Burns(mut burns)) => {
            // TODO: Rewrite rotation documentation
            let scheduler = schedulers.get_mut(
              active_keys.last().expect("burn event despite no keys").to_bytes().as_ref()
            ).unwrap();

            let mut payments = vec![];
            for out in burns.drain(..) {
              let WithAmount { data: OutInstruction { address, data }, amount } = out;
              if let Ok(address) = C::Address::try_from(address.consume()) {
                payments.push(
                  Payment { address, data: data.map(|data| data.consume()), amount: amount.0 }
                );
              }
            }

            // TODO: Handle plans
            let plans = scheduler.schedule(payments);
          }
        }
      },

      msg = key_gen.events.recv() => {
        match msg.unwrap() {
          KeyGenEvent::KeyConfirmed { set, keys } => {
            let activation_number = coin.get_latest_block_number().await.unwrap(); // TODO
            track_key(&mut schedulers, activation_number, keys.group_key());
            signers.insert(
              keys.group_key().to_bytes().as_ref().to_vec(),
              Signer::new(db.clone(), coin.clone(), keys)
            );
          },
          KeyGenEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::KeyGen(msg)).unwrap();
          },
        }
      },

      msg = scanner.events.recv() => {
        // These need to be sent to the coordinator which needs to check they aren't replayed
        // TODO
        match msg.unwrap() {
          ScannerEvent::Block(number, id) => todo!(),
          ScannerEvent::Outputs(key, block, outputs) => todo!(),
        }
      },

      (key, msg) = SignerMessageFuture(&mut signers) => {
        match msg {
          SignerEvent::SignedTransaction { id, tx } => todo!(),
          SignerEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::Sign(msg)).unwrap();
          },
        }
      },
    }
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new();
  match "TODO" {
    "bitcoin" => run(db, Bitcoin::new("TODO".to_string())).await,
    "monero" => run(db, Monero::new("TODO".to_string())).await,
    _ => panic!("unrecognized coin"),
  }
}
