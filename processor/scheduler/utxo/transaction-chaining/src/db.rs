use core::marker::PhantomData;

use group::GroupEncoding;

use serai_primitives::Coin;

use serai_db::{Get, DbTxn, create_db};

use primitives::ReceivedOutput;
use scanner::{ScannerFeed, KeyFor, OutputFor};

create_db! {
  TransactionChainingScheduler {
    SerializedOutputs: (key: &[u8], coin: Coin) -> Vec<u8>,
  }
}

pub(crate) struct Db<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> Db<S> {
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
}
