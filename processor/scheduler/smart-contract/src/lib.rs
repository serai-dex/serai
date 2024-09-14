#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{marker::PhantomData, future::Future};
use std::collections::HashMap;

use group::GroupEncoding;

use serai_db::{Get, DbTxn, create_db};

use primitives::{ReceivedOutput, Payment};
use scanner::{
  LifetimeStage, ScannerFeed, KeyFor, AddressFor, EventualityFor, BlockFor, SchedulerUpdate,
  KeyScopedEventualities, Scheduler as SchedulerTrait,
};
use scheduler_primitives::*;

create_db! {
  SmartContractScheduler {
    NextNonce: () -> u64,
  }
}

/// A smart contract.
pub trait SmartContract<S: ScannerFeed>: 'static + Send {
  /// The type representing a signable transaction.
  type SignableTransaction: SignableTransaction;

  /// Rotate from the retiring key to the new key.
  fn rotate(
    nonce: u64,
    retiring_key: KeyFor<S>,
    new_key: KeyFor<S>,
  ) -> (Self::SignableTransaction, EventualityFor<S>);
  /// Fulfill the set of payments, dropping any not worth handling.
  fn fulfill(
    starting_nonce: u64,
    payments: Vec<Payment<AddressFor<S>>>,
  ) -> Vec<(Self::SignableTransaction, EventualityFor<S>)>;
}

/// A scheduler for a smart contract representing the Serai processor.
#[allow(non_snake_case)]
#[derive(Clone, Default)]
pub struct Scheduler<S: ScannerFeed, SC: SmartContract<S>> {
  _S: PhantomData<S>,
  _SC: PhantomData<SC>,
}

fn fulfill_payments<S: ScannerFeed, SC: SmartContract<S>>(
  txn: &mut impl DbTxn,
  active_keys: &[(KeyFor<S>, LifetimeStage)],
  payments: Vec<Payment<AddressFor<S>>>,
) -> KeyScopedEventualities<S> {
  let key = match active_keys[0].1 {
    LifetimeStage::ActiveYetNotReporting |
    LifetimeStage::Active |
    LifetimeStage::UsingNewForChange => active_keys[0].0,
    LifetimeStage::Forwarding | LifetimeStage::Finishing => active_keys[1].0,
  };

  let mut nonce = NextNonce::get(txn).unwrap_or(0);
  let mut eventualities = Vec::with_capacity(1);
  for (signable, eventuality) in SC::fulfill(nonce, payments) {
    TransactionsToSign::<SC::SignableTransaction>::send(txn, &key, &signable);
    nonce += 1;
    eventualities.push(eventuality);
  }
  NextNonce::set(txn, &nonce);
  HashMap::from([(key.to_bytes().as_ref().to_vec(), eventualities)])
}

impl<S: ScannerFeed, SC: SmartContract<S>> SchedulerTrait<S> for Scheduler<S, SC> {
  type EphemeralError = ();
  type SignableTransaction = SC::SignableTransaction;

  fn activate_key(_txn: &mut impl DbTxn, _key: KeyFor<S>) {}

  fn flush_key(
    &self,
    txn: &mut impl DbTxn,
    _block: &BlockFor<S>,
    retiring_key: KeyFor<S>,
    new_key: KeyFor<S>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move {
      let nonce = NextNonce::get(txn).unwrap_or(0);
      let (signable, eventuality) = SC::rotate(nonce, retiring_key, new_key);
      NextNonce::set(txn, &(nonce + 1));
      TransactionsToSign::<SC::SignableTransaction>::send(txn, &retiring_key, &signable);
      Ok(HashMap::from([(retiring_key.to_bytes().as_ref().to_vec(), vec![eventuality])]))
    }
  }

  fn retire_key(_txn: &mut impl DbTxn, _key: KeyFor<S>) {}

  fn update(
    &self,
    txn: &mut impl DbTxn,
    _block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    update: SchedulerUpdate<S>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move {
      // We ignore the outputs as we don't need to know our current state as it never suffers
      // partial availability

      // We shouldn't have any forwards though
      assert!(update.forwards().is_empty());

      // Create the transactions for the returns
      Ok(fulfill_payments::<S, SC>(
        txn,
        active_keys,
        update
          .returns()
          .iter()
          .map(|to_return| {
            Payment::new(to_return.address().clone(), to_return.output().balance(), None)
          })
          .collect::<Vec<_>>(),
      ))
    }
  }

  fn fulfill(
    &self,
    txn: &mut impl DbTxn,
    _block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    payments: Vec<Payment<AddressFor<S>>>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move { Ok(fulfill_payments::<S, SC>(txn, active_keys, payments)) }
  }
}
