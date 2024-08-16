use tributary::{
  ReadWrite,
  transaction::{TransactionError, TransactionKind, Transaction as TransactionTrait},
  Tributary,
};

mod db;
pub use db::*;

mod spec;
pub use spec::TributarySpec;

mod transaction;
pub use transaction::{Label, SignData, Transaction};

mod signing_protocol;

mod handle;
pub use handle::*;

pub mod scanner;

pub async fn publish_signed_transaction<D: Db, P: crate::P2p>(
  txn: &mut D::Transaction<'_>,
  tributary: &Tributary<D, Transaction, P>,
  tx: Transaction,
) {
  log::debug!("publishing transaction {}", hex::encode(tx.hash()));

  let (order, signer) = if let TransactionKind::Signed(order, signed) = tx.kind() {
    let signer = signed.signer;

    // Safe as we should deterministically create transactions, meaning if this is already on-disk,
    // it's what we're saving now
    SignedTransactionDb::set(txn, &order, signed.nonce, &tx.serialize());

    (order, signer)
  } else {
    panic!("non-signed transaction passed to publish_signed_transaction");
  };

  // If we're trying to publish 5, when the last transaction published was 3, this will delay
  // publication until the point in time we publish 4
  while let Some(tx) = SignedTransactionDb::take_signed_transaction(
    txn,
    &order,
    tributary
      .next_nonce(&signer, &order)
      .await
      .expect("we don't have a nonce, meaning we aren't a participant on this tributary"),
  ) {
    // We need to return a proper error here to enable that, due to a race condition around
    // multiple publications
    match tributary.add_transaction(tx.clone()).await {
      Ok(_) => {}
      // Some asynchonicity if InvalidNonce, assumed safe to deterministic nonces
      Err(TransactionError::InvalidNonce) => {
        log::warn!("publishing TX {tx:?} returned InvalidNonce. was it already added?")
      }
      Err(e) => panic!("created an invalid transaction: {e:?}"),
    }
  }
}
