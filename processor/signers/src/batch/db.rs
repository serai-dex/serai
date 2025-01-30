use serai_validator_sets_primitives::Session;
use serai_in_instructions_primitives::{Batch, SignedBatch};

use serai_db::{Get, DbTxn, create_db};

create_db! {
  SignersBatch {
    ActiveSigningProtocols: (session: Session) -> Vec<[u8; 32]>,
    BatchHash: (id: u32) -> [u8; 32],
    Batches: (hash: [u8; 32]) -> Batch,
    SignedBatches: (id: u32) -> SignedBatch,
    LastAcknowledgedBatch: () -> u32,
  }
}
