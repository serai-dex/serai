use serai_primitives::validator_sets::Session;

serai_db::schema! {
  SignersTransaction {
    ActiveSigningProtocols: (session: Session) -> Vec<[u8; 32]>,
    SerializedSignableTransactions: (id: [u8; 32]) -> Vec<u8>,
    SerializedTransactions: (id: [u8; 32]) -> Vec<u8>,
  }
}
