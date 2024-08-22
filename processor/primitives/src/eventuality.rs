use std::collections::HashMap;
use std::io;

/// A description of a transaction which will eventually happen.
pub trait Eventuality: Sized + Send + Sync {
  /// A unique byte sequence which can be used to identify potentially resolving transactions.
  ///
  /// Both a transaction and an Eventuality are expected to be able to yield lookup sequences.
  /// Lookup sequences MUST be unique to the Eventuality and identical to any transaction's which
  /// satisfies this Eventuality. Transactions which don't satisfy this Eventuality MAY also have
  /// an identical lookup sequence.
  ///
  /// This is used to find the Eventuality a transaction MAY resolve so we don't have to check all
  /// transactions against all Eventualities. Once the potential resolved Eventuality is
  /// identified, the full check is performed.
  fn lookup(&self) -> Vec<u8>;

  /// Read an Eventuality.
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  /// Serialize an Eventuality to a `Vec<u8>`.
  fn serialize(&self) -> Vec<u8>;
}

/// A tracker of unresolved Eventualities.
#[derive(Debug)]
pub struct EventualityTracker<E: Eventuality> {
  /// The active Eventualities.
  ///
  /// These are keyed by their lookups.
  pub active_eventualities: HashMap<Vec<u8>, E>,
}
