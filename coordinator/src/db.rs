use std::{path::Path, fs};

pub(crate) use serai_db::{Get, DbTxn, Db as DbTrait};
use serai_db::{create_db, db_channel};

use dkg::Participant;

use serai_client_serai::abi::primitives::{
  crypto::KeyPair,
  network_id::ExternalNetworkId,
  validator_sets::{Session, ExternalValidatorSet},
};

use serai_env::Environment;

use serai_cosign::SignedCosign;
use serai_coordinator_substrate::NewSetInformation;
use serai_coordinator_tributary::Transaction;

#[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
pub(crate) type Db = std::sync::Arc<serai_db::ParityDb>;
#[cfg(feature = "rocksdb")]
pub(crate) type Db = serai_db::RocksDB;

#[expect(unreachable_code)]
fn db(path: &str) -> Db {
  {
    let path: &Path = path.as_ref();
    // This may error if this path already exists, which we shouldn't propagate/panic on. If this
    // is a problem (such as we don't have the necessary permissions to write to this path), we
    // expect the following DB opening to error.
    let _: Result<_, _> = fs::create_dir_all(path.parent().unwrap());
  }

  #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
  panic!("built with parity-db and rocksdb");
  #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
  let db = serai_db::new_parity_db(path);
  #[cfg(feature = "rocksdb")]
  let db = serai_db::new_rocksdb(path);
  db
}

pub(crate) fn coordinator_db(env: &Environment) -> Db {
  let root_path = &**env.var("DB_PATH").expect("path to DB wasn't specified");
  db(&format!("{root_path}/coordinator/db"))
}

fn tributary_db_folder(env: &Environment, set: ExternalValidatorSet) -> String {
  let root_path = &**env.var("DB_PATH").expect("path to DB wasn't specified");
  let network = match set.network {
    ExternalNetworkId::Bitcoin => "Bitcoin",
    ExternalNetworkId::Ethereum => "Ethereum",
    ExternalNetworkId::Monero => "Monero",
  };
  format!("{root_path}/tributary-{network}-{}", set.session.0)
}

pub(crate) fn tributary_db(env: &Environment, set: ExternalValidatorSet) -> Db {
  db(&format!("{}/db", tributary_db_folder(env, set)))
}

pub(crate) fn prune_tributary_db(env: &Environment, set: ExternalValidatorSet) {
  serai_env::info!("pruning data directory for tributary {set:?}");
  let db = tributary_db_folder(env, set);
  if fs::exists(&db).expect("couldn't check if tributary DB exists") {
    fs::remove_dir_all(db).unwrap();
  }
}

create_db! {
  Coordinator {
    // The currently active Tributaries
    ActiveTributaries: () -> Vec<NewSetInformation>,
    // The latest Tributary to have been retired for a network
    // Since Tributaries are retired sequentially, this is informative to if any Tributary has been
    // retired
    RetiredTributary: (network: ExternalNetworkId) -> Session,
    // The last handled message from a Processor
    LastProcessorMessage: (network: ExternalNetworkId) -> u64,
    // Cosigns we produced and tried to intake yet incurred an error while doing so
    ErroneousCosigns: () -> Vec<SignedCosign>,
    // The keys to confirm and set on the Serai network
    KeysToConfirm: (set: ExternalValidatorSet) -> KeyPair,
    // The key was set on the Serai network
    KeySet: (set: ExternalValidatorSet) -> (),
  }
}

db_channel! {
  Coordinator {
    // Cosigns we produced
    SignedCosigns: () -> SignedCosign,
    // Tributaries to clean up upon reboot
    TributaryCleanup: () -> ExternalValidatorSet,
  }
}

mod _internal_db {
  use super::*;

  db_channel! {
    Coordinator {
      // Tributary transactions to publish from the Processor messages
      TributaryTransactionsFromProcessorMessages: (set: ExternalValidatorSet) -> Transaction,
      // Tributary transactions to publish from the DKG confirmation task
      TributaryTransactionsFromDkgConfirmation: (set: ExternalValidatorSet) -> Transaction,
      // Participants to remove
      RemoveParticipant: (set: ExternalValidatorSet) -> u16,
    }
  }
}

pub(crate) struct TributaryTransactionsFromProcessorMessages;
impl TributaryTransactionsFromProcessorMessages {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ExternalValidatorSet, tx: &Transaction) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::TributaryTransactionsFromProcessorMessages::send(txn, set, tx);
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> Option<Transaction> {
    _internal_db::TributaryTransactionsFromProcessorMessages::try_recv(txn, set)
  }
}

pub(crate) struct TributaryTransactionsFromDkgConfirmation;
impl TributaryTransactionsFromDkgConfirmation {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ExternalValidatorSet, tx: &Transaction) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::TributaryTransactionsFromDkgConfirmation::send(txn, set, tx);
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> Option<Transaction> {
    _internal_db::TributaryTransactionsFromDkgConfirmation::try_recv(txn, set)
  }
}

pub(crate) struct RemoveParticipant;
impl RemoveParticipant {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ExternalValidatorSet, participant: Participant) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::RemoveParticipant::send(txn, set, &u16::from(participant));
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> Option<Participant> {
    _internal_db::RemoveParticipant::try_recv(txn, set)
      .map(|i| Participant::new(i).expect("sent invalid participant index for removal"))
  }
}
