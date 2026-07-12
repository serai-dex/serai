use serai_db::{Get, Transaction as DbTxn};

use serai_primitives::validator_sets::Session;

serai_db::schema!(
  ScannerBatch {
    // The last session to sign a Batch and their first Batch signed
    LastSessionToSignBatchAndFirstBatch: () -> (Session, u32),
  }
);

pub(crate) struct BatchDb;
impl BatchDb {
  pub(crate) fn set_last_session_to_sign_batch_and_first_batch(
    txn: &mut (impl Send + DbTxn),
    session: Session,
    id: u32,
  ) {
    LastSessionToSignBatchAndFirstBatch::set(txn, &(session, id));
  }
  pub(crate) fn last_session_to_sign_batch_and_first_batch(
    getter: &impl Get,
  ) -> Option<(Session, u32)> {
    LastSessionToSignBatchAndFirstBatch::get(getter)
  }
}
