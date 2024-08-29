use core::marker::PhantomData;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use primitives::{EncodableG, Eventuality, EventualityTracker};

use crate::{ScannerFeed, KeyFor, EventualityFor};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

create_db!(
  ScannerEventuality {
    // The next block to check for resolving eventualities
    NextToCheckForEventualitiesBlock: () -> u64,
    // The latest block this task has handled which was notable
    LatestHandledNotableBlock: () -> u64,

    SerializedEventualities: <K: Encode>(key: K) -> Vec<u8>,

    RetiredKey: <K: Borshy>(block_number: u64) -> K,
  }
);

pub(crate) struct EventualityDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> EventualityDb<S> {
  pub(crate) fn set_next_to_check_for_eventualities_block(
    txn: &mut impl DbTxn,
    next_to_check_for_eventualities_block: u64,
  ) {
    NextToCheckForEventualitiesBlock::set(txn, &next_to_check_for_eventualities_block);
  }
  pub(crate) fn next_to_check_for_eventualities_block(getter: &impl Get) -> Option<u64> {
    NextToCheckForEventualitiesBlock::get(getter)
  }

  pub(crate) fn set_latest_handled_notable_block(
    txn: &mut impl DbTxn,
    latest_handled_notable_block: u64,
  ) {
    LatestHandledNotableBlock::set(txn, &latest_handled_notable_block);
  }
  pub(crate) fn latest_handled_notable_block(getter: &impl Get) -> Option<u64> {
    LatestHandledNotableBlock::get(getter)
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

  pub(crate) fn retire_key(txn: &mut impl DbTxn, block_number: u64, key: KeyFor<S>) {
    assert!(
      RetiredKey::get::<EncodableG<KeyFor<S>>>(txn, block_number).is_none(),
      "retiring multiple keys within the same block"
    );
    RetiredKey::set(txn, block_number, &EncodableG(key));
  }
  pub(crate) fn take_retired_key(txn: &mut impl DbTxn, block_number: u64) -> Option<KeyFor<S>> {
    let res = RetiredKey::get::<EncodableG<KeyFor<S>>>(txn, block_number).map(|res| res.0);
    if res.is_some() {
      RetiredKey::del::<EncodableG<KeyFor<S>>>(txn, block_number);
    }
    res
  }
}
