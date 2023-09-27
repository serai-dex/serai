#[cfg(feature = "binaries")]
mod messages;
#[cfg(feature = "binaries")]
mod queue;

#[cfg(feature = "binaries")]
mod binaries {
  pub(crate) use std::{
    sync::{Arc, RwLock},
    collections::HashMap,
  };

  pub(crate) use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
  pub(crate) use schnorr_signatures::SchnorrSignature;

  pub(crate) use serai_primitives::NetworkId;

  use serai_db::{Get, DbTxn, Db as DbTrait};

  pub(crate) use jsonrpsee::{RpcModule, server::ServerBuilder};

  pub(crate) use crate::messages::*;

  pub(crate) use crate::queue::Queue;

  pub(crate) type Db = serai_db::RocksDB;

  #[allow(clippy::type_complexity)]
  mod clippy {
    use super::*;
    lazy_static::lazy_static! {
      pub(crate) static ref KEYS: Arc<RwLock<HashMap<Service, <Ristretto as Ciphersuite>::G>>> =
        Arc::new(RwLock::new(HashMap::new()));
      pub(crate) static ref QUEUES: Arc<RwLock<HashMap<(Service, Service), RwLock<Queue<Db>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    }
  }
  pub(crate) use self::clippy::*;

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
    db: &RwLock<Db>,
    meta: Metadata,
    msg: Vec<u8>,
    sig: SchnorrSignature<Ristretto>,
  ) {
    {
      let from = (*KEYS).read().unwrap()[&meta.from];
      assert!(
        sig.verify(from, message_challenge(meta.from, from, meta.to, &meta.intent, &msg, sig.R))
      );
    }

    // Assert one, and only one of these, is the coordinator
    assert!(matches!(meta.from, Service::Coordinator) ^ matches!(meta.to, Service::Coordinator));

    // Verify (from, intent) hasn't been prior seen
    // At the time of writing, intents should be unique even across `from`. There's a DoS where
    // a service sends another service's intent, causing the other service to have their message
    // dropped though.
    // Including from prevents that DoS, and allows simplifying intents to solely unique within
    // a service (not within all of Serai).
    fn key(domain: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
      [&[u8::try_from(domain.len()).unwrap()], domain, key.as_ref()].concat()
    }
    fn intent_key(from: Service, to: Service, intent: &[u8]) -> Vec<u8> {
      key(b"intent_seen", bincode::serialize(&(from, to, intent)).unwrap())
    }
    let mut db = db.write().unwrap();
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
    let id = (*QUEUES).read().unwrap()[&(meta.from, meta.to)].write().unwrap().queue_message(
      &mut txn,
      QueuedMessage {
        from: meta.from,
        // Temporary value which queue_message will override
        id: u64::MAX,
        msg,
        sig: sig.serialize(),
      },
    );

    log::info!("Queued message from {:?}. It is {:?} {id}", meta.from, meta.to);
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
    let queue_outer = (*QUEUES).read().unwrap();
    let queue = queue_outer[&(from, to)].read().unwrap();
    let next = queue.last_acknowledged().map(|i| i + 1).unwrap_or(0);
    queue.get_message(next)
  }

  // ack RPC method
  /*
    Acknowledges a message as received and handled, meaning it'll no longer be returned as the next
    message.
  */
  pub(crate) fn ack_message(from: Service, to: Service, id: u64, sig: SchnorrSignature<Ristretto>) {
    {
      let to_key = (*KEYS).read().unwrap()[&to];
      assert!(sig.verify(to_key, ack_challenge(to, to_key, from, id, sig.R)));
    }

    // Is it:
    // The acknowledged message should be > last acknowledged OR
    // The acknowledged message should be >=
    // It's the first if we save messages as acknowledged before acknowledging them
    // It's the second if we acknowledge messages before saving them as acknowledged
    // TODO: Check only a proper message is being acked

    log::info!("{:?} is acknowledging {:?} {}", from, to, id);

    (*QUEUES).read().unwrap()[&(from, to)].write().unwrap().ack_message(id)
  }
}

#[cfg(feature = "binaries")]
#[tokio::main]
async fn main() {
  use binaries::*;

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
  let db = serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));

  let read_key = |str| {
    let key = serai_env::var(str)?;

    let mut repr = <<Ristretto as Ciphersuite>::G as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(&hex::decode(key).unwrap());
    Some(<Ristretto as Ciphersuite>::G::from_bytes(&repr).unwrap())
  };

  const ALL_EXT_NETWORKS: [NetworkId; 3] =
    [NetworkId::Bitcoin, NetworkId::Ethereum, NetworkId::Monero];

  let register_service = |service, key| {
    (*KEYS).write().unwrap().insert(service, key);
    let mut queues = (*QUEUES).write().unwrap();
    if service == Service::Coordinator {
      for network in ALL_EXT_NETWORKS {
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

  // Make queues for each NetworkId, other than Serai
  for network in ALL_EXT_NETWORKS {
    // Use a match so we error if the list of NetworkIds changes
    let Some(key) = read_key(match network {
      NetworkId::Serai => unreachable!(),
      NetworkId::Bitcoin => "BITCOIN_KEY",
      NetworkId::Ethereum => "ETHEREUM_KEY",
      NetworkId::Monero => "MONERO_KEY",
    }) else {
      continue;
    };

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

  let mut module = RpcModule::new(RwLock::new(db));
  module
    .register_method("queue", |args, db| {
      let args = args.parse::<(Metadata, Vec<u8>, Vec<u8>)>().unwrap();
      queue_message(
        db,
        args.0,
        args.1,
        SchnorrSignature::<Ristretto>::read(&mut args.2.as_slice()).unwrap(),
      );
      Ok(true)
    })
    .unwrap();
  module
    .register_method("next", |args, _| {
      let (from, to) = args.parse::<(Service, Service)>().unwrap();
      Ok(get_next_message(from, to))
    })
    .unwrap();
  module
    .register_method("ack", |args, _| {
      let args = args.parse::<(Service, Service, u64, Vec<u8>)>().unwrap();
      ack_message(
        args.0,
        args.1,
        args.2,
        SchnorrSignature::<Ristretto>::read(&mut args.3.as_slice()).unwrap(),
      );
      Ok(true)
    })
    .unwrap();

  // Run until stopped, which it never will
  server.start(module).unwrap().stopped().await;
}

#[cfg(not(feature = "binaries"))]
fn main() {
  panic!("To run binaries, please build with `--feature binaries`.");
}
