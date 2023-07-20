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

type Db = Arc<rocksdb::TransactionDB>;

lazy_static::lazy_static! {
  static ref KEYS: Arc<RwLock<HashMap<Service, <Ristretto as Ciphersuite>::G>>> =
    Arc::new(RwLock::new(HashMap::new()));
  static ref QUEUES: Arc<RwLock<HashMap<Service, RwLock<Queue<Db>>>>> =
    Arc::new(RwLock::new(HashMap::new()));
}

// queue RPC method
/*
  Queues a message to be delivered from a processor to a coordinator, or vice versa.

  Messages are authenticated to be coming from the claimed service. Recipient services SHOULD
  independently verify signatures.

  The metadata specifies an intent. Only one message, for a specified intent, will be delivered.
  This allows services to safely send messages multiple times without them being delivered multiple
  times.

  The message will be ordered by this service, with the order having no guarantees other than
  successful ordering by the time this call returns.
*/
fn queue_message(meta: Metadata, msg: Vec<u8>, sig: SchnorrSignature<Ristretto>) {
  {
    let from = (*KEYS).read().unwrap()[&meta.from];
    assert!(
      sig.verify(from, message_challenge(meta.from, from, meta.to, &meta.intent, &msg, sig.R))
    );
  }

  // Assert one, and only one of these, is the coordinator
  assert!(matches!(meta.from, Service::Coordinator) ^ matches!(meta.to, Service::Coordinator));

  // TODO: Verify (from, intent) hasn't been prior seen

  // Queue it
  let id = (*QUEUES).read().unwrap()[&meta.to].write().unwrap().queue_message(QueuedMessage {
    from: meta.from,
    // Temporary value which queue_message will override
    id: u64::MAX,
    msg,
    sig: sig.serialize(),
  });

  log::info!("Queued message from {:?}. It is {:?} {id}", meta.from, meta.to);
}

// next RPC method
/*
  Gets the next message in queue for this service.

  This is not authenticated due to the fact every nonce would have to be saved to prevent replays,
  or a challenge-response protocol implemented. Neither are worth doing when there should be no
  sensitive data on this server.

  The expected index is used to ensure a service didn't fall out of sync with this service. It
  should always be either the next message's ID or *TODO*.
*/
fn get_next_message(service: Service, _expected: u64) -> Option<QueuedMessage> {
  // TODO: Verify the expected next message ID matches

  let queue_outer = (*QUEUES).read().unwrap();
  let queue = queue_outer[&service].read().unwrap();
  let next = queue.last_acknowledged().map(|i| i + 1).unwrap_or(0);
  queue.get_message(next)
}

// ack RPC method
/*
  Acknowledges a message as received and handled, meaning it'll no longer be returned as the next
  message.
*/
fn ack_message(service: Service, id: u64, sig: SchnorrSignature<Ristretto>) {
  {
    let from = (*KEYS).read().unwrap()[&service];
    assert!(sig.verify(from, ack_challenge(service, from, id, sig.R)));
  }

  // Is it:
  // The acknowledged message should be > last acknowledged OR
  // The acknowledged message should be >=
  // It's the first if we save messages as acknowledged before acknowledging them
  // It's the second if we acknowledge messages before saving them as acknowledged
  // TODO: Check only a proper message is being acked

  log::info!("{:?} is acknowledging {}", service, id);

  (*QUEUES).read().unwrap()[&service].write().unwrap().ack_message(id)
}

#[tokio::main]
async fn main() {
  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", "info");
  }
  env_logger::init();

  log::info!("Starting message-queue service...");

  // Open the DB
  let db = Arc::new(
    rocksdb::TransactionDB::open_default(
      serai_env::var("DB_PATH").expect("path to DB wasn't specified"),
    )
    .unwrap(),
  );

  let read_key = |str| {
    let key = serai_env::var(str)?;

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
  // TODO: Add middleware to check some key is present in the header, making this an authed
  // connection
  // TODO: Set max request/response size
  // 5132 ^ ((b'M' << 8) | b'Q')
  let listen_on: &[std::net::SocketAddr] = &["0.0.0.0:2287".parse().unwrap()];
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
      Ok(true)
    })
    .unwrap();
  module
    .register_method("next", |args, _| {
      let args = args.parse::<(Service, u64)>().unwrap();
      Ok(get_next_message(args.0, args.1))
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
      Ok(true)
    })
    .unwrap();

  // Run until stopped, which it never will
  server.start(module).unwrap().stopped().await;
}
