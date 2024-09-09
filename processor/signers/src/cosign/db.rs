use serai_validator_sets_primitives::Session;

use serai_db::{Get, DbTxn, create_db};

create_db! {
  SignersCosigner {
    LatestCosigned: (session: Session) -> u64,
  }
}
