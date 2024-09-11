use serai_db::{Get, DbTxn, create_db};

create_db! {
  BitcoinProcessor {
    LatestBlockToYieldAsFinalized: () -> u64,
    ScriptPubKey: (tx: [u8; 32], vout: u32) -> Vec<u8>,
  }
}
