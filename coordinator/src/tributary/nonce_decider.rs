use serai_db::{Get, DbTxn, create_db};

use processor_messages::coordinator::SubstrateSignableId;

use crate::tributary::Transaction;

use scale::Encode;

const SUBSTRATE_CODE: u8 = 0;
const SUBSTRATE_SIGNING_CODE: u8 = 1;
const PLAN_CODE: u8 = 2;
const PLAN_SIGNING_CODE: u8 = 3;

create_db!(
  NonceDeciderDb {
    NextNonceDb: (genesis: [u8; 32]) -> u32,
    ItemNonceDb: (genesis: [u8; 32], code: u8, id: &[u8]) -> u32,
  }
);

impl NextNonceDb {
  pub fn allocate_nonce(txn: &mut impl DbTxn, genesis: [u8; 32]) -> u32 {
    let next = Self::get(txn, genesis).unwrap_or(3);
    Self::set(txn, genesis, &(next + 1));
    next
  }
}

/// Decides the nonce which should be used for a transaction on a Tributary.
///
/// Deterministically builds a list of nonces to use based on the on-chain events and expected
/// transactions in response. Enables rebooting/rebuilding validators with full safety.
pub struct NonceDecider;
impl NonceDecider {
  pub fn handle_substrate_signable(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    id: SubstrateSignableId,
  ) -> u32 {
    let nonce_for = NextNonceDb::allocate_nonce(txn, genesis);
    ItemNonceDb::set(txn, genesis, SUBSTRATE_CODE, &id.encode(), &nonce_for);
    nonce_for
  }

  pub fn handle_substrate_block(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    plans: &[[u8; 32]],
  ) -> Vec<u32> {
    let mut res = Vec::with_capacity(plans.len());
    for plan in plans {
      let nonce_for = NextNonceDb::allocate_nonce(txn, genesis);
      ItemNonceDb::set(txn, genesis, PLAN_CODE, plan, &nonce_for);
      res.push(nonce_for);
    }
    res
  }

  // TODO: The processor won't yield shares for this if the signing protocol aborts. We need to
  // detect when we're expecting shares for an aborted protocol and insert a dummy transaction
  // there.
  pub fn selected_for_signing_substrate(
    txn: &mut impl DbTxn,
    genesis: [u8; 32],
    id: SubstrateSignableId,
  ) {
    let nonce_for = NextNonceDb::allocate_nonce(txn, genesis);
    ItemNonceDb::set(txn, genesis, SUBSTRATE_SIGNING_CODE, &id.encode(), &nonce_for);
  }

  // TODO: Same TODO as selected_for_signing_substrate
  pub fn selected_for_signing_plan(txn: &mut impl DbTxn, genesis: [u8; 32], plan: [u8; 32]) {
    let nonce_for = NextNonceDb::allocate_nonce(txn, genesis);
    ItemNonceDb::set(txn, genesis, PLAN_SIGNING_CODE, &plan, &nonce_for);
  }

  pub fn nonce(getter: &impl Get, genesis: [u8; 32], tx: &Transaction) -> Option<Option<u32>> {
    match tx {
      Transaction::RemoveParticipant(_) => None,

      Transaction::DkgCommitments(attempt, _, _) => {
        assert_eq!(*attempt, 0);
        Some(Some(0))
      }
      Transaction::DkgShares { attempt, .. } => {
        assert_eq!(*attempt, 0);
        Some(Some(1))
      }
      // InvalidDkgShare and DkgConfirmed share a nonce due to the expected existence of only one
      // on-chain
      Transaction::InvalidDkgShare { attempt, .. } => {
        assert_eq!(*attempt, 0);
        Some(Some(2))
      }
      Transaction::DkgConfirmed(attempt, _, _) => {
        assert_eq!(*attempt, 0);
        Some(Some(2))
      }

      Transaction::CosignSubstrateBlock(_) => None,

      Transaction::Batch(_, _) => None,
      Transaction::SubstrateBlock(_) => None,
      Transaction::SubstratePreprocess(data) => {
        assert_eq!(data.attempt, 0);
        Some(ItemNonceDb::get(getter, genesis, SUBSTRATE_CODE, &data.plan.encode()))
      }
      Transaction::SubstrateShare(data) => {
        assert_eq!(data.attempt, 0);
        Some(ItemNonceDb::get(getter, genesis, SUBSTRATE_SIGNING_CODE, &data.plan.encode()))
      }
      Transaction::SignPreprocess(data) => {
        assert_eq!(data.attempt, 0);
        Some(ItemNonceDb::get(getter, genesis, PLAN_CODE, &data.plan.encode()))
      }
      Transaction::SignShare(data) => {
        assert_eq!(data.attempt, 0);
        Some(ItemNonceDb::get(getter, genesis, PLAN_SIGNING_CODE, &data.plan.encode()))
      }
      Transaction::SignCompleted { .. } => None,
    }
  }
}
