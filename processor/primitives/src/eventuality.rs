use std::{io, collections::HashMap};

use crate::Id;

/// A description of a transaction which will eventually happen.
pub trait Eventuality: Sized + Send + Sync {
  /// The type used to identify a received output.
  type OutputId: Id;

  /// The ID of the SignableTransaction this Eventuality is for.
  ///
  /// This is an internal ID arbitrarily definable so long as it's unique.
  fn id(&self) -> [u8; 32];

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

  /// The output the resolution of this Eventuality was supposed to spend.
  ///
  /// If the resolution of this Eventuality has multiple inputs, there is no singular spent output
  /// so this MUST return None.
  fn singular_spent_output(&self) -> Option<Self::OutputId>;

  /// Read an Eventuality.
  fn read(reader: &mut impl io::Read) -> io::Result<Self>;
  /// Write an Eventuality.
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()>;
}

/// A tracker of unresolved Eventualities.
#[derive(Debug)]
pub struct EventualityTracker<E: Eventuality> {
  /// The active Eventualities.
  ///
  /// These are keyed by their lookups.
  pub active_eventualities: HashMap<Vec<u8>, E>,
}

impl<E: Eventuality> Default for EventualityTracker<E> {
  fn default() -> Self {
    EventualityTracker { active_eventualities: HashMap::new() }
  }
}

impl<E: Eventuality> EventualityTracker<E> {
  /// Insert an Eventuality into the tracker.
  pub fn insert(&mut self, eventuality: E) {
    self.active_eventualities.insert(eventuality.lookup(), eventuality);
  }
}
