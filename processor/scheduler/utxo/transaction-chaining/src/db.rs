use core::marker::PhantomData;

use group::GroupEncoding as _;

use serai_primitives::{coin::ExternalCoin, balance::Amount};

use serai_db::{Get, Transaction as DbTxn};

use primitives::{Payment, ReceivedOutput};
use scanner::{ScannerFeed, KeyFor, AddressFor, OutputFor};

serai_db::schema! {
  TransactionChainingScheduler {
    OperatingCosts: (coin: ExternalCoin) -> Amount,
    SerializedOutputs: (key: &[u8], coin: ExternalCoin) -> Vec<u8>,
    AlreadyAccumulatedOutput: (id: &[u8]) -> (),
    // We should be immediately able to schedule the fulfillment of payments, yet this may not be
    // possible if we're in the middle of a multisig rotation (as our output set will be split)
    SerializedQueuedPayments: (key: &[u8], coin: ExternalCoin) -> Vec<u8>,
  }
}

pub(crate) struct Db<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> Db<S> {
  pub(crate) fn operating_costs(getter: &impl Get, coin: ExternalCoin) -> Amount {
    OperatingCosts::get(getter, coin).unwrap_or(Amount(0))
  }
  pub(crate) fn set_operating_costs(txn: &mut impl DbTxn, coin: ExternalCoin, amount: Amount) {
    OperatingCosts::set(txn, coin, &amount);
  }

  pub(crate) fn outputs(
    getter: &impl Get,
    key: KeyFor<S>,
    coin: ExternalCoin,
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
    coin: ExternalCoin,
    outputs: &[OutputFor<S>],
  ) {
    let mut buf = Vec::with_capacity(outputs.len() * 128);
    for output in outputs {
      output.write(&mut buf).unwrap();
    }
    SerializedOutputs::set(txn, key.to_bytes().as_ref(), coin, &buf);
  }
  pub(crate) fn del_outputs(txn: &mut impl DbTxn, key: KeyFor<S>, coin: ExternalCoin) {
    SerializedOutputs::del(txn, key.to_bytes().as_ref(), coin);
  }

  pub(crate) fn set_already_accumulated_output(
    txn: &mut impl DbTxn,
    output: &<OutputFor<S> as ReceivedOutput<KeyFor<S>, AddressFor<S>>>::Id,
  ) {
    AlreadyAccumulatedOutput::set(txn, output.as_ref(), &());
  }
  pub(crate) fn take_if_already_accumulated_output(
    txn: &mut impl DbTxn,
    output: &<OutputFor<S> as ReceivedOutput<KeyFor<S>, AddressFor<S>>>::Id,
  ) -> bool {
    AlreadyAccumulatedOutput::take(txn, output.as_ref()).is_some()
  }

  pub(crate) fn queued_payments(
    getter: &impl Get,
    key: KeyFor<S>,
    coin: ExternalCoin,
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
    coin: ExternalCoin,
    queued: &[Payment<AddressFor<S>>],
  ) {
    let mut buf = Vec::with_capacity(queued.len() * 128);
    for queued in queued {
      queued.write(&mut buf).unwrap();
    }
    SerializedQueuedPayments::set(txn, key.to_bytes().as_ref(), coin, &buf);
  }
  pub(crate) fn del_queued_payments(txn: &mut impl DbTxn, key: KeyFor<S>, coin: ExternalCoin) {
    SerializedQueuedPayments::del(txn, key.to_bytes().as_ref(), coin);
  }
}
