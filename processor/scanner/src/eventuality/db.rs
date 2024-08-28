use core::marker::PhantomData;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use primitives::EventualityTracker;

use crate::{ScannerFeed, KeyFor, EventualityFor};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

create_db!(
  ScannerEventuality {
    // The next block to check for resolving eventualities
    NextToCheckForEventualitiesBlock: () -> u64,

    SerializedEventualities: <K: Borshy>() -> Vec<u8>,
  }
);

pub(crate) struct EventualityDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> EventualityDb<S> {
  pub(crate) fn set_next_to_check_for_eventualities_block(
    txn: &mut impl DbTxn,
    next_to_check_for_eventualities_block: u64,
  ) {
    assert!(
      next_to_check_for_eventualities_block != 0,
      "next-to-check-for-eventualities block was 0 when it's bound non-zero"
    );
    NextToCheckForEventualitiesBlock::set(txn, &next_to_check_for_eventualities_block);
  }
  pub(crate) fn next_to_check_for_eventualities_block(getter: &impl Get) -> Option<u64> {
    NextToCheckForEventualitiesBlock::get(getter)
  }

  pub(crate) fn set_eventualities(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    eventualities: &EventualityTracker<EventualityFor<S>>,
  ) {
    todo!("TODO")
  }

  pub(crate) fn eventualities(
    getter: &impl Get,
    key: KeyFor<S>,
  ) -> EventualityTracker<EventualityFor<S>> {
    todo!("TODO")
  }
}
