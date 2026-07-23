use serai_primitives::validator_sets::Session;

serai_db::schema! {
  SignersCosigner {
    LatestCosigned: (session: Session) -> u64,
  }
}
