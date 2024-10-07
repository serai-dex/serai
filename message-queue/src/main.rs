pub(crate) use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

pub(crate) use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
pub(crate) use schnorr_signatures::SchnorrSignature;

pub(crate) use serai_primitives::ExternalNetworkId;

pub(crate) use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
};

use serai_db::{Get, DbTxn, Db as DbTrait};

pub(crate) use crate::messages::*;

pub(crate) use crate::queue::Queue;

#[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
pub(crate) type Db = Arc<serai_db::ParityDb>;
#[cfg(feature = "rocksdb")]
pub(crate) type Db = serai_db::RocksDB;

#[allow(clippy::type_complexity)]
mod clippy {
  use super::*;
  use once_cell::sync::Lazy;
  pub(crate) static KEYS: Lazy<Arc<RwLock<HashMap<Service, <Ristretto as Ciphersuite>::G>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));
  pub(crate) static QUEUES: Lazy<Arc<RwLock<HashMap<(Service, Service), RwLock<Queue<Db>>>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));
}
pub(crate) use self::clippy::*;

mod messages;
mod queue;

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

// queue RPC method
/*
  Queues a message to be delivered from a processor to a coordinator, or vice versa.

  Messages are authenticated to be coming from the claimed service. Recipient services SHOULD
  independently verify signatures.

  The metadata specifies an intent. Only one message, for a specified intent, will be delivered.
  This allows services to safely send messages multiple times without them being delivered
  multiple times.

  The message will be ordered by this service, with the order having no guarantees other than
  successful ordering by the time this call returns.
*/
pub(crate) fn queue_message(
  db: &mut Db,
  meta: &Metadata,
  msg: Vec<u8>,
  sig: SchnorrSignature<Ristretto>,
) {
  {
    let from = KEYS.read().unwrap()[&meta.from];
    assert!(
      sig.verify(from, message_challenge(meta.from, from, meta.to, &meta.intent, &msg, sig.R))
    );
  }

  // Assert one, and only one of these, is the coordinator
  assert!(matches!(meta.from, Service::Coordinator) ^ matches!(meta.to, Service::Coordinator));

  // Verify (from, to, intent) hasn't been prior seen
  fn key(domain: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [&[u8::try_from(domain.len()).unwrap()], domain, key.as_ref()].concat()
  }
  fn intent_key(from: Service, to: Service, intent: &[u8]) -> Vec<u8> {
    key(b"intent_seen", borsh::to_vec(&(from, to, intent)).unwrap())
  }
  let mut txn = db.txn();
  let intent_key = intent_key(meta.from, meta.to, &meta.intent);
  if Get::get(&txn, &intent_key).is_some() {
    log::warn!(
      "Prior queued message attempted to be queued again. From: {:?} To: {:?} Intent: {}",
      meta.from,
      meta.to,
      hex::encode(&meta.intent)
    );
    return;
  }
  DbTxn::put(&mut txn, intent_key, []);

  // Queue it
  let id = QUEUES.read().unwrap()[&(meta.from, meta.to)].write().unwrap().queue_message(
    &mut txn,
    QueuedMessage {
      from: meta.from,
      // Temporary value which queue_message will override
      id: u64::MAX,
      msg,
      sig: sig.serialize(),
    },
  );

  log::info!("Queued message. From: {:?} To: {:?} ID: {id}", meta.from, meta.to);
  DbTxn::commit(txn);
}

// next RPC method
/*
  Gets the next message in queue for the named services.

  This is not authenticated due to the fact every nonce would have to be saved to prevent
  replays, or a challenge-response protocol implemented. Neither are worth doing when there
  should be no sensitive data on this server.
*/
pub(crate) fn get_next_message(from: Service, to: Service) -> Option<QueuedMessage> {
  let queue_outer = QUEUES.read().unwrap();
  let queue = queue_outer[&(from, to)].read().unwrap();
  let next = queue.last_acknowledged().map_or(0, |i| i + 1);
  queue.get_message(next)
}

// ack RPC method
/*
  Acknowledges a message as received and handled, meaning it'll no longer be returned as the next
  message.
*/
pub(crate) fn ack_message(from: Service, to: Service, id: u64, sig: SchnorrSignature<Ristretto>) {
  {
    let to_key = KEYS.read().unwrap()[&to];
    assert!(sig.verify(to_key, ack_challenge(to, to_key, from, id, sig.R)));
  }

  // Is it:
  // The acknowledged message should be > last acknowledged OR
  // The acknowledged message should be >=
  // It's the first if we save messages as acknowledged before acknowledging them
  // It's the second if we acknowledge messages before saving them as acknowledged
  // TODO: Check only a proper message is being acked

  log::info!("Acknowledging From: {:?} To: {:?} ID: {}", from, to, id);

  QUEUES.read().unwrap()[&(from, to)].write().unwrap().ack_message(id)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
  // Override the panic handler with one which will panic if any tokio task panics
  {
    let existing = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
      existing(panic);
      const MSG: &str = "exiting the process due to a task panicking";
      println!("{MSG}");
      log::error!("{MSG}");
      std::process::exit(1);
    }));
  }

  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_string()));
  }
  env_logger::init();

  log::info!("Starting message-queue service...");

  // Open the DB
  #[allow(unused_variables, unreachable_code)]
  let db = {
    #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
    panic!("built with parity-db and rocksdb");
    #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
    let db =
      serai_db::new_parity_db(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    #[cfg(feature = "rocksdb")]
    let db =
      serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    db
  };

  let read_key = |str| {
    let key = serai_env::var(str)?;

    let mut repr = <<Ristretto as Ciphersuite>::G as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(&hex::decode(key).unwrap());
    Some(<Ristretto as Ciphersuite>::G::from_bytes(&repr).unwrap())
  };

  let register_service = |service, key| {
    KEYS.write().unwrap().insert(service, key);
    let mut queues = QUEUES.write().unwrap();
    if service == Service::Coordinator {
      for network in serai_primitives::EXTERNAL_NETWORKS {
        queues.insert(
          (service, Service::Processor(network)),
          RwLock::new(Queue(db.clone(), service, Service::Processor(network))),
        );
      }
    } else {
      queues.insert(
        (service, Service::Coordinator),
        RwLock::new(Queue(db.clone(), service, Service::Coordinator)),
      );
    }
  };

  // Make queues for each ExternalNetworkId
  for network in serai_primitives::EXTERNAL_NETWORKS {
    // Use a match so we error if the list of NetworkIds changes
    let Some(key) = read_key(match network {
      ExternalNetworkId::Bitcoin => "BITCOIN_KEY",
      ExternalNetworkId::Ethereum => "ETHEREUM_KEY",
      ExternalNetworkId::Monero => "MONERO_KEY",
    }) else {
      continue;
    };

    register_service(Service::Processor(network), key);
  }

  // And the coordinator's
  register_service(Service::Coordinator, read_key("COORDINATOR_KEY").unwrap());

  // Start server
  // 5132 ^ ((b'M' << 8) | b'Q')
  let server = TcpListener::bind("0.0.0.0:2287").await.unwrap();

  loop {
    let (mut socket, _) = server.accept().await.unwrap();
    // TODO: Add a magic value with a key at the start of the connection to make this authed
    let mut db = db.clone();
    tokio::spawn(async move {
      loop {
        let Ok(msg_len) = socket.read_u32_le().await else { break };
        let mut buf = vec![0; usize::try_from(msg_len).unwrap()];
        let Ok(_) = socket.read_exact(&mut buf).await else { break };
        let msg = borsh::from_slice(&buf).unwrap();

        match msg {
          MessageQueueRequest::Queue { meta, msg, sig } => {
            queue_message(
              &mut db,
              &meta,
              msg,
              SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()).unwrap(),
            );
            let Ok(()) = socket.write_all(&[1]).await else { break };
          }
          MessageQueueRequest::Next { from, to } => match get_next_message(from, to) {
            Some(msg) => {
              let Ok(()) = socket.write_all(&[1]).await else { break };
              let msg = borsh::to_vec(&msg).unwrap();
              let len = u32::try_from(msg.len()).unwrap();
              let Ok(()) = socket.write_all(&len.to_le_bytes()).await else { break };
              let Ok(()) = socket.write_all(&msg).await else { break };
            }
            None => {
              let Ok(()) = socket.write_all(&[0]).await else { break };
            }
          },
          MessageQueueRequest::Ack { from, to, id, sig } => {
            ack_message(
              from,
              to,
              id,
              SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()).unwrap(),
            );
            let Ok(()) = socket.write_all(&[1]).await else { break };
          }
        }
      }
    });
  }
}
