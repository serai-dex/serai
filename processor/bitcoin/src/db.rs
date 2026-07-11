serai_db::schema! {
  BitcoinProcessor {
    LatestBlockToYieldAsFinalized: () -> u64,
    ScriptPubKey: (tx: [u8; 32], vout: u32) -> Vec<u8>,
  }
}
