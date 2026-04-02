use serai_primitives::validator_sets::Session;

use serai_db::{Get, DbTxn, create_db};

create_db! {
  SignersCosigner {
    LatestCosigned: (session: Session) -> u64,
  }
}
