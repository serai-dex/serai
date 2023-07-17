use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use schnorr_signatures::SchnorrSignature;

use serai_primitives::NetworkId;

use jsonrpsee::{RpcModule, server::ServerBuilder};

mod messages;
use messages::*;

mod queue;
use queue::Queue;

lazy_static::lazy_static! {
  static ref KEYS: Arc<RwLock<HashMap<Service, <Ristretto as Ciphersuite>::G>>> =
    Arc::new(RwLock::new(HashMap::new()));
  static ref QUEUES: Arc<RwLock<HashMap<Service, RwLock<Queue<serai_db::MemDb>>>>> =
    Arc::new(RwLock::new(HashMap::new()));
}

// queue RPC method
fn queue_message(meta: Metadata, msg: Vec<u8>, sig: SchnorrSignature<Ristretto>) {
  {
    let from = (*KEYS).read().unwrap()[&meta.from];
    assert!(sig.verify(from, message_challenge(from, meta.to, &meta.intent, &msg, sig.R)));
  }

  // Assert one, and only one of these, is the coordinator
  assert!(matches!(meta.from, Service::Coordinator) ^ matches!(meta.to, Service::Coordinator));

  // TODO: Verify the intent hasn't been prior seen

  // Queue it
  (*QUEUES).read().unwrap()[&meta.to].write().unwrap().queue_message(QueuedMessage {
    from: meta.from,
    msg,
    sig: sig.serialize(),
  });
}

// get RPC method
fn get_next_message(service: Service, _expected: u64) -> Option<QueuedMessage> {
  // TODO: Verify the expected next message ID matches

  let queue_outer = (*QUEUES).read().unwrap();
  let queue = queue_outer[&service].read().unwrap();
  let next = queue.last_acknowledged().map(|i| i + 1).unwrap_or(0);
  queue.get_message(next)
}

// ack RPC method
fn ack_message(service: Service, id: u64, _signature: SchnorrSignature<Ristretto>) {
  // TODO: Verify the signature

  // Is it:
  // The acknowledged message should be > last acknowledged OR
  // The acknowledged message should be >=
  // It's the first if we save messages as acknowledged before acknowledging them
  // It's the second if we acknowledge messages before saving them as acknowledged
  // TODO: Check only a proper message is being acked

  (*QUEUES).read().unwrap()[&service].write().unwrap().ack_message(id)
}

#[tokio::main]
async fn main() {
  // Open the DB
  // TODO
  let db = serai_db::MemDb::new();

  let read_key = |str| {
    let Ok(key) = std::env::var(str) else { None? };

    let mut repr = <<Ristretto as Ciphersuite>::G as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(&hex::decode(key).unwrap());
    Some(<Ristretto as Ciphersuite>::G::from_bytes(&repr).unwrap())
  };

  let register_service = |service, key| {
    (*KEYS).write().unwrap().insert(service, key);
    (*QUEUES).write().unwrap().insert(service, RwLock::new(Queue(db.clone(), service)));
  };

  // Make queues for each NetworkId, other than Serai
  for network in [NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero] {
    // Use a match so we error if the list of NetworkIds changes
    let Some(key) = read_key(match network {
      NetworkId::Serai => unreachable!(),
      NetworkId::Bitcoin => "BITCOIN_KEY",
      NetworkId::Ethereum => "ETHEREUM_KEY",
      NetworkId::Monero => "MONERO_KEY",
    }) else { continue };

    register_service(Service::Processor(network), key);
  }

  // And the coordinator's
  register_service(Service::Coordinator, read_key("COORDINATOR_KEY").unwrap());

  // Start server
  let builder = ServerBuilder::new();
  // TODO: Set max request/response size
  let listen_on: &[std::net::SocketAddr] = &["0.0.0.0".parse().unwrap()];
  let server = builder.build(listen_on).await.unwrap();

  let mut module = RpcModule::new(());
  module
    .register_method("queue", |args, _| {
      let args = args.parse::<(Metadata, Vec<u8>, Vec<u8>)>().unwrap();
      queue_message(
        args.0,
        args.1,
        SchnorrSignature::<Ristretto>::read(&mut args.2.as_slice()).unwrap(),
      );
      Ok(())
    })
    .unwrap();
  module
    .register_method("next", |args, _| {
      let args = args.parse::<(Service, u64, Vec<u8>)>().unwrap();
      get_next_message(args.0, args.1);
      Ok(())
    })
    .unwrap();
  module
    .register_method("ack", |args, _| {
      let args = args.parse::<(Service, u64, Vec<u8>)>().unwrap();
      ack_message(
        args.0,
        args.1,
        SchnorrSignature::<Ristretto>::read(&mut args.2.as_slice()).unwrap(),
      );
      Ok(())
    })
    .unwrap();
  server.start(module).unwrap();
}
