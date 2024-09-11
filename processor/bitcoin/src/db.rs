use ciphersuite::group::GroupEncoding;

use serai_client::validator_sets::primitives::Session;

use serai_db::{Get, DbTxn, create_db, db_channel};
use primitives::EncodableG;

create_db! {
  Processor {
    ExternalKeyForSessionForSigners: <K: GroupEncoding>(session: Session) -> EncodableG<K>,
  }
}

db_channel! {
  Processor {
    KeyToActivate: <K: GroupEncoding>() -> EncodableG<K>
  }
}

create_db! {
  BitcoinProcessor {
    LatestBlockToYieldAsFinalized: () -> u64,
    ScriptPubKey: (tx: [u8; 32], vout: u32) -> Vec<u8>,
  }
}
