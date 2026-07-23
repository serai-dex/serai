use serai_primitives::{
  validator_sets::Session,
  instructions::{Batch, SignedBatch},
};

serai_db::schema! {
  SignersBatch {
    ActiveSigningProtocols: (session: Session) -> Vec<[u8; 32]>,
    BatchHash: (id: u32) -> [u8; 32],
    Batches: (hash: [u8; 32]) -> Batch,
    SignedBatches: (id: u32) -> SignedBatch,
    LastAcknowledgedBatch: () -> u32,
  }
}
