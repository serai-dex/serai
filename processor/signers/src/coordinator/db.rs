use serai_db::{Get, DbTxn, create_db};

create_db! {
  SignersCoordinator {
    LastPublishedBatch: () -> u32,
  }
}
