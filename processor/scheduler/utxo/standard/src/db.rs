use core::marker::PhantomData;

use group::GroupEncoding;

use serai_primitives::{Coin, Amount, Balance};

use borsh::BorshDeserialize;
use serai_db::{Get, DbTxn, create_db, db_channel};

use primitives::{Payment, ReceivedOutput};
use utxo_scheduler_primitives::TreeTransaction;
use scanner::{ScannerFeed, KeyFor, AddressFor, OutputFor};

create_db! {
  UtxoScheduler {
    OperatingCosts: (coin: Coin) -> Amount,
    SerializedOutputs: (key: &[u8], coin: Coin) -> Vec<u8>,
    SerializedQueuedPayments: (key: &[u8], coin: Coin) -> Vec<u8>,
  }
}

db_channel! {
  UtxoScheduler {
    PendingBranch: (key: &[u8], balance: Balance) -> Vec<u8>,
  }
}

pub(crate) struct Db<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> Db<S> {
  pub(crate) fn operating_costs(getter: &impl Get, coin: Coin) -> Amount {
    OperatingCosts::get(getter, coin).unwrap_or(Amount(0))
  }
  pub(crate) fn set_operating_costs(txn: &mut impl DbTxn, coin: Coin, amount: Amount) {
    OperatingCosts::set(txn, coin, &amount)
  }

  pub(crate) fn outputs(
    getter: &impl Get,
    key: KeyFor<S>,
    coin: Coin,
  ) -> Option<Vec<OutputFor<S>>> {
    let buf = SerializedOutputs::get(getter, key.to_bytes().as_ref(), coin)?;
    let mut buf = buf.as_slice();

    let mut res = Vec::with_capacity(buf.len() / 128);
    while !buf.is_empty() {
      res.push(OutputFor::<S>::read(&mut buf).unwrap());
    }
    Some(res)
  }
  pub(crate) fn set_outputs(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    coin: Coin,
    outputs: &[OutputFor<S>],
  ) {
    let mut buf = Vec::with_capacity(outputs.len() * 128);
    for output in outputs {
      output.write(&mut buf).unwrap();
    }
    SerializedOutputs::set(txn, key.to_bytes().as_ref(), coin, &buf);
  }
  pub(crate) fn del_outputs(txn: &mut impl DbTxn, key: KeyFor<S>, coin: Coin) {
    SerializedOutputs::del(txn, key.to_bytes().as_ref(), coin);
  }

  pub(crate) fn queued_payments(
    getter: &impl Get,
    key: KeyFor<S>,
    coin: Coin,
  ) -> Option<Vec<Payment<AddressFor<S>>>> {
    let buf = SerializedQueuedPayments::get(getter, key.to_bytes().as_ref(), coin)?;
    let mut buf = buf.as_slice();

    let mut res = Vec::with_capacity(buf.len() / 128);
    while !buf.is_empty() {
      res.push(Payment::read(&mut buf).unwrap());
    }
    Some(res)
  }
  pub(crate) fn set_queued_payments(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    coin: Coin,
    queued: &[Payment<AddressFor<S>>],
  ) {
    let mut buf = Vec::with_capacity(queued.len() * 128);
    for queued in queued {
      queued.write(&mut buf).unwrap();
    }
    SerializedQueuedPayments::set(txn, key.to_bytes().as_ref(), coin, &buf);
  }
  pub(crate) fn del_queued_payments(txn: &mut impl DbTxn, key: KeyFor<S>, coin: Coin) {
    SerializedQueuedPayments::del(txn, key.to_bytes().as_ref(), coin);
  }

  pub(crate) fn queue_pending_branch(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    balance: Balance,
    child: &TreeTransaction<AddressFor<S>>,
  ) {
    PendingBranch::send(txn, key.to_bytes().as_ref(), balance, &borsh::to_vec(child).unwrap())
  }
  pub(crate) fn take_pending_branch(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    balance: Balance,
  ) -> Option<TreeTransaction<AddressFor<S>>> {
    PendingBranch::try_recv(txn, key.to_bytes().as_ref(), balance)
      .map(|bytes| TreeTransaction::<AddressFor<S>>::deserialize(&mut bytes.as_slice()).unwrap())
  }
}
