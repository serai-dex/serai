use serai_client::validator_sets::primitives::Session;

use serai_db::{Get, DbTxn, create_db};

create_db! {
  Processor {
    ExternalKeyForSession: (session: Session) -> Vec<u8>,
  }
}

create_db! {
  BitcoinProcessor {
    LatestBlockToYieldAsFinalized: () -> u64,
    ScriptPubKey: (tx: [u8; 32], vout: u32) -> Vec<u8>,
  }
}
