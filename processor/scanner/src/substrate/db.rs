use core::marker::PhantomData;

use group::GroupEncoding;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db, db_channel};

use serai_coins_primitives::OutInstructionWithBalance;

use messages::substrate::ExecutedBatch;

use crate::{ScannerFeed, KeyFor};

#[derive(BorshSerialize, BorshDeserialize)]
struct AcknowledgeBatchEncodable {
  batch: ExecutedBatch,
  burns: Vec<OutInstructionWithBalance>,
  key_to_activate: Option<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum ActionEncodable {
  AcknowledgeBatch(AcknowledgeBatchEncodable),
  QueueBurns(Vec<OutInstructionWithBalance>),
}

pub(crate) struct AcknowledgeBatch<S: ScannerFeed> {
  pub(crate) batch: ExecutedBatch,
  pub(crate) burns: Vec<OutInstructionWithBalance>,
  pub(crate) key_to_activate: Option<KeyFor<S>>,
}

pub(crate) enum Action<S: ScannerFeed> {
  AcknowledgeBatch(AcknowledgeBatch<S>),
  QueueBurns(Vec<OutInstructionWithBalance>),
}

create_db!(
  ScannerSubstrate {
    LastAcknowledgedBatch: () -> u32,
  }
);

db_channel!(
  ScannerSubstrate {
    Actions: () -> ActionEncodable,
  }
);

pub(crate) struct SubstrateDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> SubstrateDb<S> {
  pub(crate) fn last_acknowledged_batch(getter: &impl Get) -> Option<u32> {
    LastAcknowledgedBatch::get(getter)
  }

  pub(crate) fn set_last_acknowledged_batch(txn: &mut impl DbTxn, id: u32) {
    LastAcknowledgedBatch::set(txn, &id)
  }

  pub(crate) fn queue_acknowledge_batch(
    txn: &mut impl DbTxn,
    batch: ExecutedBatch,
    burns: Vec<OutInstructionWithBalance>,
    key_to_activate: Option<KeyFor<S>>,
  ) {
    Actions::send(
      txn,
      &ActionEncodable::AcknowledgeBatch(AcknowledgeBatchEncodable {
        batch,
        burns,
        key_to_activate: key_to_activate.map(|key| key.to_bytes().as_ref().to_vec()),
      }),
    );
  }
  pub(crate) fn queue_queue_burns(txn: &mut impl DbTxn, burns: Vec<OutInstructionWithBalance>) {
    Actions::send(txn, &ActionEncodable::QueueBurns(burns));
  }

  pub(crate) fn next_action(txn: &mut impl DbTxn) -> Option<Action<S>> {
    let action_encodable = Actions::try_recv(txn)?;
    Some(match action_encodable {
      ActionEncodable::AcknowledgeBatch(AcknowledgeBatchEncodable {
        batch,
        burns,
        key_to_activate,
      }) => Action::AcknowledgeBatch(AcknowledgeBatch {
        batch,
        burns,
        key_to_activate: key_to_activate.map(|key| {
          let mut repr = <KeyFor<S> as GroupEncoding>::Repr::default();
          repr.as_mut().copy_from_slice(&key);
          KeyFor::<S>::from_bytes(&repr).unwrap()
        }),
      }),
      ActionEncodable::QueueBurns(burns) => Action::QueueBurns(burns),
    })
  }
}
