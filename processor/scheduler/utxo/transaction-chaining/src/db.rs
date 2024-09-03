use core::marker::PhantomData;

use group::GroupEncoding;

use serai_primitives::{Coin, Amount};

use serai_db::{Get, DbTxn, create_db};

use primitives::{Payment, ReceivedOutput};
use scanner::{ScannerFeed, KeyFor, AddressFor, OutputFor};

create_db! {
  TransactionChainingScheduler {
    OperatingCosts: (coin: Coin) -> Amount,
    SerializedOutputs: (key: &[u8], coin: Coin) -> Vec<u8>,
    // We should be immediately able to schedule the fulfillment of payments, yet this may not be
    // possible if we're in the middle of a multisig rotation (as our output set will be split)
    SerializedQueuedPayments: (key: &[u8], coin: Coin) -> Vec<u8>,
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
    todo!("TODO")
  }
  pub(crate) fn set_queued_payments(
    txn: &mut impl DbTxn,
    key: KeyFor<S>,
    coin: Coin,
    queued: &Vec<Payment<AddressFor<S>>>,
  ) {
    todo!("TODO")
  }
  pub(crate) fn del_queued_payments(txn: &mut impl DbTxn, key: KeyFor<S>, coin: Coin) {
    SerializedQueuedPayments::del(txn, key.to_bytes().as_ref(), coin);
  }
}
