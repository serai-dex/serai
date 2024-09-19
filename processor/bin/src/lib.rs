use core::cmp::Ordering;

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite, Ristretto,
};
use dkg::evrf::EvrfCurve;

use serai_client::validator_sets::primitives::Session;

use serai_env as env;
use serai_db::{Get, DbTxn, Db as DbTrait, create_db, db_channel};

use primitives::EncodableG;
use ::key_gen::{KeyGenParams, KeyGen};
use scheduler::{SignableTransaction, TransactionFor};
use scanner::{ScannerFeed, Scanner, KeyFor, Scheduler};
use signers::{TransactionPublisher, Signers};

mod coordinator;
use coordinator::Coordinator;

create_db! {
  ProcessorBin {
    ExternalKeyForSessionForSigners: <K: GroupEncoding>(session: Session) -> EncodableG<K>,
  }
}

db_channel! {
  ProcessorBin {
    KeyToActivate: <K: GroupEncoding>() -> EncodableG<K>
  }
}

/// The type used for the database.
#[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
pub type Db = serai_db::ParityDb;
/// The type used for the database.
#[cfg(feature = "rocksdb")]
pub type Db = serai_db::RocksDB;

/// Initialize the processor.
///
/// Yields the database.
#[allow(unused_variables, unreachable_code)]
pub fn init() -> Db {
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

  #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
  let db =
    serai_db::new_parity_db(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
  #[cfg(feature = "rocksdb")]
  let db = serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
  db
}

/// THe URL for the external network's node.
pub fn url() -> String {
  let login = env::var("NETWORK_RPC_LOGIN").expect("network RPC login wasn't specified");
  let hostname = env::var("NETWORK_RPC_HOSTNAME").expect("network RPC hostname wasn't specified");
  let port = env::var("NETWORK_RPC_PORT").expect("network port domain wasn't specified");
  "http://".to_string() + &login + "@" + &hostname + ":" + &port
}

fn key_gen<K: KeyGenParams>() -> KeyGen<K> {
  fn read_key_from_env<C: Ciphersuite>(label: &'static str) -> Zeroizing<C::F> {
    let key_hex =
      Zeroizing::new(env::var(label).unwrap_or_else(|| panic!("{label} wasn't provided")));
    let bytes = Zeroizing::new(
      hex::decode(key_hex).unwrap_or_else(|_| panic!("{label} wasn't a valid hex string")),
    );

    let mut repr = <C::F as PrimeField>::Repr::default();
    if repr.as_ref().len() != bytes.len() {
      panic!("{label} wasn't the correct length");
    }
    repr.as_mut().copy_from_slice(bytes.as_slice());
    let res = Zeroizing::new(
      Option::from(<C::F as PrimeField>::from_repr(repr))
        .unwrap_or_else(|| panic!("{label} wasn't a valid scalar")),
    );
    repr.as_mut().zeroize();
    res
  }
  KeyGen::new(
    read_key_from_env::<<Ristretto as EvrfCurve>::EmbeddedCurve>("SUBSTRATE_EVRF_KEY"),
    read_key_from_env::<<K::ExternalNetworkCiphersuite as EvrfCurve>::EmbeddedCurve>(
      "NETWORK_EVRF_KEY",
    ),
  )
}

async fn first_block_after_time<S: ScannerFeed>(feed: &S, serai_time: u64) -> u64 {
  async fn first_block_after_time_iteration<S: ScannerFeed>(
    feed: &S,
    serai_time: u64,
  ) -> Result<Option<u64>, S::EphemeralError> {
    let latest = feed.latest_finalized_block_number().await?;
    let latest_time = feed.time_of_block(latest).await?;
    if latest_time < serai_time {
      tokio::time::sleep(core::time::Duration::from_secs(serai_time - latest_time)).await;
      return Ok(None);
    }

    // A finalized block has a time greater than or equal to the time we want to start at
    // Find the first such block with a binary search
    // start_search and end_search are inclusive
    let mut start_search = 0;
    let mut end_search = latest;
    while start_search != end_search {
      // This on purposely chooses the earlier block in the case two blocks are both in the middle
      let to_check = start_search + ((end_search - start_search) / 2);
      let block_time = feed.time_of_block(to_check).await?;
      match block_time.cmp(&serai_time) {
        Ordering::Less => {
          start_search = to_check + 1;
          assert!(start_search <= end_search);
        }
        Ordering::Equal | Ordering::Greater => {
          // This holds true since we pick the earlier block upon an even search distance
          // If it didn't, this would cause an infinite loop
          assert!(to_check < end_search);
          end_search = to_check;
        }
      }
    }
    Ok(Some(start_search))
  }
  loop {
    match first_block_after_time_iteration(feed, serai_time).await {
      Ok(Some(block)) => return block,
      Ok(None) => {
        log::info!("waiting for block to activate at (a block with timestamp >= {serai_time})");
      }
      Err(e) => {
        log::error!("couldn't find the first block Serai should scan due to an RPC error: {e:?}");
      }
    }
    tokio::time::sleep(core::time::Duration::from_secs(5)).await;
  }
}

/// Hooks to run during the main loop.
pub trait Hooks {
  /// A hook to run upon receiving a message.
  fn on_message(txn: &mut impl DbTxn, msg: &messages::CoordinatorMessage);
}
impl Hooks for () {
  fn on_message(_: &mut impl DbTxn, _: &messages::CoordinatorMessage) {}
}

/// The main loop of a Processor, interacting with the Coordinator.
pub async fn main_loop<
  H: Hooks,
  S: ScannerFeed,
  K: KeyGenParams<ExternalNetworkCiphersuite: Ciphersuite<G = KeyFor<S>>>,
  Sch: Clone
    + Scheduler<
      S,
      SignableTransaction: SignableTransaction<Ciphersuite = K::ExternalNetworkCiphersuite>,
    >,
>(
  mut db: Db,
  feed: S,
  scheduler: Sch,
  publisher: impl TransactionPublisher<TransactionFor<Sch::SignableTransaction>>,
) {
  let mut coordinator = Coordinator::new(db.clone());

  let mut key_gen = key_gen::<K>();
  let mut scanner = Scanner::new(db.clone(), feed.clone(), scheduler.clone()).await;
  let mut signers =
    Signers::<Db, S, Sch, _>::new(db.clone(), coordinator.coordinator_send(), publisher);

  loop {
    let db_clone = db.clone();
    let mut txn = db.txn();
    let msg = coordinator.next_message(&mut txn).await;
    H::on_message(&mut txn, &msg);
    let mut txn = Some(txn);
    match msg {
      messages::CoordinatorMessage::KeyGen(msg) => {
        let txn = txn.as_mut().unwrap();
        let mut new_key = None;
        // This is a computationally expensive call yet it happens infrequently
        for msg in key_gen.handle(txn, msg) {
          if let messages::key_gen::ProcessorMessage::GeneratedKeyPair { session, .. } = &msg {
            new_key = Some(*session)
          }
          coordinator.send_message(&messages::ProcessorMessage::KeyGen(msg));
        }

        // If we were yielded a key, register it in the signers
        if let Some(session) = new_key {
          let (substrate_keys, network_keys) = KeyGen::<K>::key_shares(txn, session)
            .expect("generated key pair yet couldn't get key shares");
          signers.register_keys(txn, session, substrate_keys, network_keys);
        }
      }

      // These are cheap calls which are fine to be here in this loop
      messages::CoordinatorMessage::Sign(msg) => {
        let txn = txn.as_mut().unwrap();
        signers.queue_message(txn, &msg)
      }
      messages::CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
          session,
          block_number,
          block,
        },
      ) => {
        let txn = txn.take().unwrap();
        signers.cosign_block(txn, session, block_number, block)
      }
      messages::CoordinatorMessage::Coordinator(
        messages::coordinator::CoordinatorMessage::SignSlashReport { session, report },
      ) => {
        let txn = txn.take().unwrap();
        signers.sign_slash_report(txn, session, &report)
      }

      messages::CoordinatorMessage::Substrate(msg) => match msg {
        messages::substrate::CoordinatorMessage::SetKeys { serai_time, session, key_pair } => {
          let txn = txn.as_mut().unwrap();
          let key =
            EncodableG(K::decode_key(key_pair.1.as_ref()).expect("invalid key set on serai"));

          // Queue the key to be activated upon the next Batch
          KeyToActivate::<KeyFor<S>>::send(txn, &key);

          // Set the external key, as needed by the signers
          ExternalKeyForSessionForSigners::<KeyFor<S>>::set(txn, session, &key);

          // This is presumed extremely expensive, potentially blocking for several minutes, yet
          // only happens for the very first set of keys
          if session == Session(0) {
            assert!(scanner.is_none());
            let start_block = first_block_after_time(&feed, serai_time).await;
            scanner = Some(
              Scanner::initialize(db_clone, feed.clone(), scheduler.clone(), start_block, key.0)
                .await,
            );
          }
        }
        messages::substrate::CoordinatorMessage::SlashesReported { session } => {
          let txn = txn.as_mut().unwrap();

          // Since this session had its slashes reported, it has finished all its signature
          // protocols and has been fully retired. We retire it from the signers accordingly
          let key = ExternalKeyForSessionForSigners::<KeyFor<S>>::take(txn, session).unwrap().0;

          // This is a cheap call
          signers.retire_session(txn, session, &key)
        }
        messages::substrate::CoordinatorMessage::BlockWithBatchAcknowledgement {
          block: _,
          batch_id,
          in_instruction_succeededs,
          burns,
        } => {
          let mut txn = txn.take().unwrap();
          let scanner = scanner.as_mut().unwrap();
          let key_to_activate = KeyToActivate::<KeyFor<S>>::try_recv(&mut txn).map(|key| key.0);
          // This is a cheap call as it internally just queues this to be done later
          scanner.acknowledge_batch(
            txn,
            batch_id,
            in_instruction_succeededs,
            burns,
            key_to_activate,
          )
        }
        messages::substrate::CoordinatorMessage::BlockWithoutBatchAcknowledgement {
          block: _,
          burns,
        } => {
          let txn = txn.take().unwrap();
          let scanner = scanner.as_mut().unwrap();
          // This is a cheap call as it internally just queues this to be done later
          scanner.queue_burns(txn, burns)
        }
      },
    };
    // If the txn wasn't already consumed and committed, commit it
    if let Some(txn) = txn {
      txn.commit();
    }
  }
}
