use core::marker::PhantomData;

use scale::Encode;
use serai_db::{Get, DbTxn, create_db};

use primitives::{EncodableG, Eventuality, EventualityTracker};

use crate::{ScannerFeed, KeyFor, EventualityFor};

create_db!(
  ScannerEventuality {
    // The next block to check for resolving eventualities
    NextToCheckForEventualitiesBlock: () -> u64,

    SerializedEventualities: <K: Encode>(key: K) -> Vec<u8>,
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
    let mut serialized = Vec::with_capacity(eventualities.active_eventualities.len() * 128);
    for eventuality in eventualities.active_eventualities.values() {
      eventuality.write(&mut serialized).unwrap();
    }
    SerializedEventualities::set(txn, EncodableG(key), &serialized);
  }

  pub(crate) fn eventualities(
    getter: &impl Get,
    key: KeyFor<S>,
  ) -> EventualityTracker<EventualityFor<S>> {
    let serialized = SerializedEventualities::get(getter, EncodableG(key)).unwrap_or(vec![]);
    let mut serialized = serialized.as_slice();

    let mut res = EventualityTracker::default();
    while !serialized.is_empty() {
      let eventuality = EventualityFor::<S>::read(&mut serialized).unwrap();
      res.insert(eventuality);
    }
    res
  }
}
