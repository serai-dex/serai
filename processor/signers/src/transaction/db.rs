use serai_validator_sets_primitives::Session;

use serai_db::{Get, DbTxn, create_db};

create_db! {
  TransactionSigner {
    ActiveSigningProtocols: (session: Session) -> Vec<[u8; 32]>,
    SerializedSignableTransactions: (id: [u8; 32]) -> Vec<u8>,
    SerializedTransactions: (id: [u8; 32]) -> Vec<u8>,
  }
}
