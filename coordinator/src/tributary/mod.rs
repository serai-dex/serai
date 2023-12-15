use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_client::validator_sets::primitives::ValidatorSet;

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

pub fn removed_as_of_dkg_attempt(
  getter: &impl Get,
  genesis: [u8; 32],
  attempt: u32,
) -> Option<Vec<<Ristretto as Ciphersuite>::G>> {
  if attempt == 0 {
    Some(vec![])
  } else {
    FatalSlashesAsOfDkgAttempt::get(getter, genesis, attempt).map(|keys| {
      keys.iter().map(|key| <Ristretto as Ciphersuite>::G::from_bytes(key).unwrap()).collect()
    })
  }
}

pub fn latest_removed(getter: &impl Get, genesis: [u8; 32]) -> Vec<<Ristretto as Ciphersuite>::G> {
  #[allow(clippy::unwrap_or_default)]
  FatalSlashes::get(getter, genesis)
    .unwrap_or(vec![])
    .iter()
    .map(|key| <Ristretto as Ciphersuite>::G::from_bytes(key).unwrap())
    .collect()
}

pub fn removed_as_of_set_keys(
  getter: &impl Get,
  set: ValidatorSet,
  genesis: [u8; 32],
) -> Option<Vec<<Ristretto as Ciphersuite>::G>> {
  // SeraiDkgCompleted has the key placed on-chain.
  // This key can be uniquely mapped to an attempt so long as one participant was honest, which we
  // assume as a presumably honest participant.
  // Resolve from generated key to attempt to fatally slashed as of attempt.

  // This expect will trigger if this is prematurely called and Substrate has tracked the keys yet
  // we haven't locally synced and handled the Tributary
  // All callers of this, at the time of writing, ensure the Tributary has sufficiently synced
  // making the panic with context more desirable than the None
  let attempt = KeyToDkgAttempt::get(getter, SeraiDkgCompleted::get(getter, set)?)
    .expect("key completed on-chain didn't have an attempt related");
  removed_as_of_dkg_attempt(getter, genesis, attempt)
}

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
