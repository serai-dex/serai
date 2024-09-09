use serai_validator_sets_primitives::Session;
use serai_in_instructions_primitives::{Batch, SignedBatch};

use serai_db::{Get, DbTxn, create_db};

create_db! {
  BatchSigner {
    ActiveSigningProtocols: (session: Session) -> Vec<u32>,
    Batches: (id: u32) -> Batch,
    SignedBatches: (id: u32) -> SignedBatch,
    LastAcknowledgedBatch: () -> u32,
  }
}
